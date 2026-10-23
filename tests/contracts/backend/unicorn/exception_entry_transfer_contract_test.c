/* Synthetic #NP delivery/return contract using the production Unicorn helpers.
 * The run loop follows the published resume address through the guest gateway
 * and stack-reload wrapper. BCC 3.1 supplies the measured client state; the
 * host locked stack is synthetic and the client data limit is inferred. */
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "exception_frame.h"
#include "unicorn_context.h"
#include "unicorn_services.h"
#include "transition_artifacts.h"

enum {
  k_gdtr_operand = 0x0080,
  k_idtr_operand = 0x0086,
  k_idt_address = 0x1000,
  k_idt_limit = 0x3ff,
  k_entry_address = 0x1400,
  /* Measured BCC selectors distinguish client LDT code/data from handler GDT code.
   * The locked stack, landing pad, and unexpected-vector park are test-owned additions. */
  k_handler_selector = 0x0008,
  k_ldt_selector = 0x0030,
  k_locked_stack_selector = 0x0048,
  k_gateway_selector = 0x0028,
  k_host_code_selector = 0x0060,
  k_park_selector = 0x0070,
  k_client_code_selector = 0x00b4,
  k_client_data_selector = 0x0124,
  k_api_selector = 0x00d4,
  k_second_api_selector = 0x0104,
  /* Descriptor slots in the LDT, which the transition builder requires to be
   * eight-byte aligned. Guest selectors index them as slot | 4h. */
  k_client_code_slot = 0x00b0,
  k_client_data_slot = 0x0120,
  k_api_slot = 0x00d0,
  k_second_api_slot = 0x0100,
  /* Bases and limits as recorded, except the locked stack, the client data
   * limit, and the two host-owned segments. */
  k_handler_code_base = 0x000108d0,
  k_client_code_base = 0x00061000,
  k_client_code_limit = 0x5540,
  k_client_data_base = 0x00072000,
  k_locked_stack_base = k_dpmi_exception_locked_stack_base,
  k_locked_stack_limit = 0x0fff,
  k_locked_stack_sp = 0x0ff0,
  /* Host gateway and a separate synthetic far-return landing pad. */
  k_gateway_base = 0x00002000,
  k_gateway_offset = 0x0380,
  k_gateway_saved_ax_offset = 0x03a0,
  k_gateway_pointer_offset = 0x03a2,
  k_host_code_base = 0x00003000,
  k_park_base = 0x00040000,
  /* The recorded API code descriptor: base 009c1530h, limit 137eh, non-present
   * (P=0) 16-bit code at DPL 0. */
  k_api_base = 0x009c1530,
  k_api_limit = 0x137e,
  k_api_access = 0x1a,
  k_second_api_base = 0x009c15f0,
  k_second_api_limit = 0x0052,
  k_bootstrap_offset = 0x0000,
  k_client_stub_offset = 0x0100,
  k_client_fault_offset = 0x015a,
  k_handler_offset = 0x2f53,
  /* The audited route, one filler after every instruction. */
  k_gateway_route_size = 30,
  /* The captured client state, as recorded. */
  k_client_entry_sp = 0xffb0,
  k_client_flags = 0x0282,
  /* Return to the interrupted client after the five-byte far call, not to the host landing pad. */
  k_far_call_size = 5,
  k_return_ip = k_client_fault_offset + k_far_call_size,
  k_second_fault_offset = k_return_ip,
  k_return_cs = k_client_code_selector,
  k_instruction_budget = 10000,
  /* One round to the fault and the transfer's stop, one to re-enter, and one
   * more when a handler return reloads the interrupted client stack. */
  k_session_rounds = 2,
  k_session_return_rounds = 3,
  k_unexpected_vector = 0xffff,
};

/* Independent expected constants catch drift in production values. */
_Static_assert((int)k_gateway_selector == (int)k_dpmi_exception_gateway_selector,
               "the gateway selector is part of the audited contract");
_Static_assert((int)k_gateway_offset == (int)k_dpmi_exception_gateway_offset,
               "the gateway offset is part of the audited contract");
_Static_assert((uint32_t)k_gateway_base + (uint32_t)k_gateway_offset ==
                 (uint32_t)k_dpmi_exception_gateway_linear,
               "the gateway linear address is the descriptor base plus the offset");
_Static_assert((int)k_gateway_saved_ax_offset == (int)k_dpmi_exception_saved_ax_offset,
               "the saved AX cell is part of the audited route");
_Static_assert((int)k_gateway_pointer_offset == (int)k_dpmi_exception_handler_pointer_offset,
               "the installed handler cell is part of the audited route");
_Static_assert((uint32_t)k_locked_stack_base == (uint32_t)k_dpmi_exception_locked_stack_base &&
                 (uint32_t)k_locked_stack_limit == (uint32_t)k_dpmi_exception_locked_stack_limit &&
                 (int)k_locked_stack_sp == (int)k_dpmi_exception_locked_stack_sp,
               "the locked stack is part of the audited contract");

/* The recorded client general registers, in the order used by `k_gpr_regs`. */
static const uint16_t k_client_gprs[7] = {0x2c06, 0x8707, 0x0000, 0x0000, 0x009c, 0x0023, 0xffc2};

static const uint8_t k_preamble[] = {
  0xfa,                               /* cli */
  0x2e, 0x0f, 0x01, 0x1e, 0x86, 0x00, /* lidt cs:[0x86] */
  0x2e, 0x0f, 0x01, 0x16, 0x80, 0x00, /* lgdt cs:[0x80] */
  0x0f, 0x20, 0xc0,                   /* mov eax,cr0 */
  0x66, 0x83, 0xc8, 0x01,             /* or eax,0x1 */
  0x0f, 0x22, 0xc0,                   /* mov cr0,eax */
  0xea, 0x00, 0x00, 0x08, 0x00        /* jmp far 0x8:0x0 */
};

/* DPMILOAD's code segment at 0008:0000: load the LDT system selector 0030h, then
 * enter the client code segment 00b4:0100h. */
static const uint8_t k_bootstrap[] = {
  0xb8, 0x30, 0x00,            /* mov ax,0x30 */
  0x0f, 0x00, 0xd0,            /* lldt ax */
  0xea, 0x00, 0x01, 0xb4, 0x00 /* jmp far 0xb4:0x100 */
};

/* The recorded client state: DS=ES=SS=0124h, SP=ffb0h, one recorded value per
 * general register, then EFLAGS=0282h through push/popf. The far call through
 * the non-present selector is appended separately so the faulting IP is the
 * observed 015ah. `mov sp,imm16` leaves IF alone, so the captured flags carry
 * it. */
static const uint8_t k_client_setup[] = {
  0xb8, 0x24, 0x01, /* mov ax,0x124 */
  0x8e, 0xd8,       /* mov ds,ax */
  0x8e, 0xc0,       /* mov es,ax */
  0x8e, 0xd0,       /* mov ss,ax */
  0xbc, 0xb0, 0xff, /* mov sp,0xffb0 */
  0xb8, 0x06, 0x2c, /* mov ax,0x2c06 */
  0xbb, 0x07, 0x87, /* mov bx,0x8707 */
  0xb9, 0x00, 0x00, /* mov cx,0x0 */
  0xba, 0x00, 0x00, /* mov dx,0x0 */
  0xbe, 0x9c, 0x00, /* mov si,0x9c */
  0xbf, 0x23, 0x00, /* mov di,0x23 */
  0xbd, 0xc2, 0xff, /* mov bp,0xffc2 */
  0x68, 0x82, 0x02, /* push 0x282 */
  0x9d,             /* popf */
};

/* Unicorn 2.1.4 can re-enter one byte late after MOV SS; keep each instruction
 * filler. CS-relative scratch preserves AX without client DS, and DI stays intact.
 * The exact cell encoding avoids Unicorn mis-decoding displacement bytes. */
static const uint8_t k_gateway_route[k_gateway_route_size] = {
  0xfa,                         /* cli                       */
  0x90,                         /* filler                    */
  0x2e, 0x89, 0x06, 0xa0, 0x03, /* mov cs:[di+03a0], ax      */
  0x90,                         /* filler                    */
  0xb8, 0x48, 0x00,             /* mov ax, 0048h             */
  0x90,                         /* filler                    */
  0x8e, 0xd0,                   /* mov ss, ax                */
  0x90,                         /* filler                    */
  0xbc, 0xf0, 0x0f,             /* mov sp, 0ff0h             */
  0x90,                         /* filler                    */
  0x2e, 0x8b, 0x06, 0xa0, 0x03, /* mov ax, cs:[di+03a0]      */
  0x90,                         /* filler                    */
  0x2e, 0xff, 0x2e, 0xa2, 0x03, /* jmp far cs:[di+03a2]      */
};

/* `cli; hlt`: park unexpected vectors and handlers in negative cases. */
static const uint8_t k_park[] = {
  0xfa, /* cli */
  0xf4  /* hlt */
};

/* At entry the audited frame begins with its return IP and CS. This direct
 * lret witnesses the product's one-shot exception-return transition. */
static const uint8_t k_handler_return[] = {
  0xcb /* retf */
};

typedef struct {
  int failed;
  int captured;
  int classified;
  int transferred;
  int reached_gateway;
  int reached_entry;
  uint32_t unexpected_vector;
  uint16_t error_code;
  uint32_t fault_linear;
  uint16_t fault_cs, fault_ip, fault_ds, fault_es, fault_ss, fault_sp;
  uint16_t fault_gprs[7];
  uint32_t fault_eflags;
  uint16_t gateway_cs, gateway_ip, gateway_ds, gateway_es, gateway_ss, gateway_sp;
  uint16_t gateway_gprs[7];
  uint32_t gateway_eflags;
  uint16_t entry_cs, entry_ip, entry_ds, entry_es, entry_ss, entry_sp;
  uint16_t entry_gprs[7];
  uint32_t entry_eflags;
  uint64_t entry_linear;
  uint32_t frame_linear;
  uint8_t frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  uint8_t locked_stack_db;
  uint64_t gateway_bytes_read;
  uint8_t gateway_bytes[k_gateway_route_size];
  uint64_t resume_address;
  int resume_armed;
  /* Observe the runner's explicit re-entry and interrupt-dispatch decisions. */
  unsigned emulation_runs;
  unsigned entry_hook_hits;
  unsigned stale_dispatches;
  int transferred_still_armed;
  unsigned client_return_hits;
  unsigned retried_fault_hits;
  unsigned second_fault_hits;
  unsigned second_fault_vectors;
  unsigned nested_depth;
  uint32_t nested_parent_frame_linear;
  uint32_t nested_child_frame_linear;
  uint8_t nested_parent_frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  uint8_t nested_child_frame[DAZE_DPMI_EXCEPTION_FRAME_SIZE];
  int restart_seen;
  uint16_t returned_ss, returned_sp;
  uint32_t returned_eflags;
  uint16_t returned_gprs[7];
  int return_reached;
  int fault_selector_made_present;
} Contract;

/* The installed 0203h vector the classifier requires, the context the product
 * functions publish into, and the negative-case switches. */
typedef struct Session {
  Contract contract;
  DazeUnicornContext context;
  DazeDosfsFileService files;
  DazeDosfsMounts mounts;
  DazeDosfsHandles handles;
  int use_software_int;
  int omit_installed_vector;
  int present_far_call;
  int delivered_vector;
  int return_handler;
  int make_fault_selector_present;
  int repeated_fault;
  int repeated_fault_les;
  int restart_after_return;
} Session;

static const int k_gpr_regs[7] = {UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
                                  UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP};

static void read_gprs(uc_engine *uc, uint16_t *gprs) {
  for (size_t index = 0; index < 7; ++index)
    gprs[index] = get_reg16(uc, k_gpr_regs[index]);
}

typedef struct {
  uint16_t cs, ip, ds, es, ss, sp;
  uint16_t gprs[7];
  uint32_t eflags;
} State;

static State read_state(uc_engine *uc) {
  State state;
  state.cs = get_reg16(uc, UC_X86_REG_CS);
  state.ip = get_reg16(uc, UC_X86_REG_IP);
  state.ds = get_reg16(uc, UC_X86_REG_DS);
  state.es = get_reg16(uc, UC_X86_REG_ES);
  state.ss = get_reg16(uc, UC_X86_REG_SS);
  state.sp = get_reg16(uc, UC_X86_REG_SP);
  state.eflags = get_reg32(uc, UC_X86_REG_EFLAGS);
  read_gprs(uc, state.gprs);
  return state;
}

static void check(Contract *contract, int condition, const char *format, ...) {
  if (condition) return;
  va_list args;
  va_start(args, format);
  fprintf(stderr, "  CHECK FAILED: ");
  vfprintf(stderr, format, args);
  fprintf(stderr, "\n");
  va_end(args);
  contract->failed = 1;
}

/* Resolve a selector's base from the guest's own descriptor tables, honouring
 * TI: the client code segment 00b4h lives in the LDT, the handler 0008h in the
 * GDT. Descriptor bases are never derived from selector numbers. */
static int selector_base(uc_engine *uc, uint16_t selector, uint32_t *base) {
  const uint32_t table = (selector & 4u) ? k_dpmi_ldt_address : k_dpmi_gdt_address;
  uint8_t bytes[8] = {0};
  if (uc_mem_read(uc, table + (selector & 0xfff8u), bytes, sizeof(bytes)) != UC_ERR_OK) return 0;
  *base = (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8) | ((uint32_t)bytes[4] << 16) |
          ((uint32_t)bytes[7] << 24);
  return 1;
}

/* The #NP error code must match the decoded far-call selector operand. */
static int decode_far_call_selector(uc_engine *uc, uint32_t linear, uint16_t *selector) {
  uint8_t bytes[5] = {0};
  if (uc_mem_read(uc, linear, bytes, sizeof(bytes)) != UC_ERR_OK) return 0;
  if (bytes[0] != 0x9a) return 0;
  *selector = (uint16_t)((uint16_t)bytes[3] | (uint16_t)((uint16_t)bytes[4] << 8));
  return 1;
}

/* The recorded client's state, then the boundary itself. The positive session
 * far-calls the non-present LDT selector 00d4h, which is the observed faulting
 * instruction. A software `int 0Bh` at the same address reaches the same
 * Unicorn vector without that instruction, which the classifier must reject. */
static int build_client_stub(uc_engine *uc, const Session *session) {
  const size_t padding = k_client_fault_offset - k_client_stub_offset - sizeof(k_client_setup);
  uint8_t stub[sizeof(k_client_setup) + 64 + 5 + 2];
  if (padding + sizeof(k_client_setup) + 5 + 2 > sizeof(stub)) return 0;
  memcpy(stub, k_client_setup, sizeof(k_client_setup));
  memset(stub + sizeof(k_client_setup), 0x90, padding);
  uint8_t boundary[5];
  if (session->use_software_int) {
    boundary[0] = 0xcd;
    boundary[1] = 0x0b;
  } else {
    boundary[0] = 0x9a;
    boundary[1] = 0x00;
    boundary[2] = 0x00;
    boundary[3] = (uint8_t)k_api_selector;
    boundary[4] = (uint8_t)(k_api_selector >> 8);
  }
  memcpy(stub + sizeof(k_client_setup) + padding, boundary, sizeof(boundary));
  uint8_t *const continuation = stub + sizeof(k_client_setup) + padding + sizeof(boundary);
  size_t continuation_size = sizeof(k_park);
  if (session->repeated_fault_les) {
    /* Set an ordinary data pointer, then load its deliberately non-present LDT
     * selector through the exact `LES DI, ES:[BX]` form admitted by runtime. */
    static const uint8_t les[] = {
      0xbb, 0x00, 0x01, /* mov bx,0x100 */
      0x26, 0xc4, 0x3f, /* les di,DWORD PTR es:[bx] */
      0xf4              /* hlt */
    };
    memcpy(continuation, les, sizeof(les));
    const uint8_t pointer[4] = {0x00, 0x00, (uint8_t)k_second_api_selector,
                                (uint8_t)(k_second_api_selector >> 8)};
    if (uc_mem_write(uc, k_client_data_base + 0x0100, pointer, sizeof(pointer)) != UC_ERR_OK)
      return 0;
    continuation_size = sizeof(les);
  } else if (session->repeated_fault) {
    continuation[0] = 0x9a;
    continuation[1] = 0x00;
    continuation[2] = 0x00;
    continuation[3] = (uint8_t)k_second_api_selector;
    continuation[4] = (uint8_t)(k_second_api_selector >> 8);
    memcpy(continuation + 5, k_park, sizeof(k_park));
  } else {
    memcpy(continuation, k_park, sizeof(k_park));
  }
  return uc_mem_write(uc, k_client_code_base + k_client_stub_offset, stub,
                      sizeof(k_client_setup) + padding + sizeof(boundary) + continuation_size) ==
         UC_ERR_OK;
}

/* Every vector, vector 0Bh included, is a 16-bit interrupt gate to the park.
 * The capture redirects the client instead of letting a delivery happen, so the
 * park is only ever reached if that redirect is missed, which the contract
 * reports rather than tolerates. The entry's fourth byte carries the selector's
 * high byte, DPL 0, the present bit and the gate type in its low nibble. */
static int build_idt(uc_engine *uc) {
  uint8_t idt[256 * 4];
  for (size_t vector = 0; vector < 256; ++vector) {
    idt[vector * 4 + 0] = 0x00;
    idt[vector * 4 + 1] = 0x00;
    idt[vector * 4 + 2] = (uint8_t)k_park_selector;
    idt[vector * 4 + 3] = (uint8_t)((k_park_selector >> 8) | 0x80u | 0x06u);
  }
  const uint8_t pseudo[6] = {(uint8_t)k_idt_limit,   (uint8_t)(k_idt_limit >> 8),   0x00,
                             (uint8_t)k_idt_address, (uint8_t)(k_idt_address >> 8), 0x00};
  return uc_mem_write(uc, k_idt_address, idt, sizeof(idt)) == UC_ERR_OK &&
         uc_mem_write(uc, k_park_base, k_park, sizeof(k_park)) == UC_ERR_OK &&
         uc_mem_write(uc, k_idtr_operand, pseudo, sizeof(pseudo)) == UC_ERR_OK;
}

/* The test observes production classification/transfer; session switches exercise
 * software INT, absent-vector, and present-selector negative cases. */
static void on_interrupt(uc_engine *uc, uint32_t intno, void *user_data) {
  Session *session = user_data;
  Contract *contract = &session->contract;
  session->delivered_vector = 1;
  if (session->repeated_fault && contract->captured && intno == 0x0b) {
    contract->second_fault_vectors++;
    uc_emu_stop(uc);
    return;
  }
  /* Keep the intercepted vector available to detect accidental redispatch
   * after the exception transfer publishes its explicit resume address. */
  session->context.run.interrupt_number = (uint8_t)intno;
  if (intno != 0x0b || contract->captured) {
    DazeUnicornInterruptContext interrupt_context = {.context = &session->context,
                                                     .files = &session->files};
    daze_on_interrupt(uc, intno, &interrupt_context);
    return;
  }
  const State fault = read_state(uc);
  contract->fault_cs = fault.cs;
  contract->fault_ip = fault.ip;
  contract->fault_ds = fault.ds;
  contract->fault_es = fault.es;
  contract->fault_ss = fault.ss;
  contract->fault_sp = fault.sp;
  contract->fault_eflags = fault.eflags;
  memcpy(contract->fault_gprs, fault.gprs, sizeof(fault.gprs));
  contract->captured = 1;

  uint32_t code_base = 0;
  if (!selector_base(uc, contract->fault_cs, &code_base) ||
      !decode_far_call_selector(uc, code_base + contract->fault_ip, &contract->error_code)) {
    contract->failed = 1;
    uc_emu_stop(uc);
    return;
  }
  contract->fault_linear = code_base + contract->fault_ip;

  DazeDpmiExceptionFault fault_record;
  if (!daze_dpmi_exception_classify(uc, &session->context.process.dpmi, &fault_record)) {
    /* A rejected boundary must leave every gateway field untouched. */
    contract->classified = 0;
    return;
  }
  contract->classified = 1;
  if (!daze_dpmi_exception_transfer(uc, &session->context.engine, &session->context.run,
                                    &session->context.process.dpmi, &fault_record)) {
    contract->failed = 1;
    uc_emu_stop(uc);
  }
}

/* Observe gateway/handler entry, return, and the restored client context
 * while the production hooks own the exception transfer. */
static void on_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
  Session *session = user_data;
  Contract *contract = &session->contract;
  (void)size;
  if (address == (uint64_t)k_park_base) {
    contract->unexpected_vector = k_unexpected_vector;
    contract->failed = 1;
    uc_emu_stop(uc);
    return;
  }
  if (address == (uint64_t)k_client_code_base + k_client_fault_offset) {
    DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(&session->context.run);
    if (transfer != NULL && transfer->return_reached) {
      contract->retried_fault_hits++;
      uc_emu_stop(uc);
      return;
    }
  }
  if (!contract->reached_gateway && address == (uint64_t)k_gateway_base + k_gateway_offset) {
    const State gateway = read_state(uc);
    contract->reached_gateway = 1;
    contract->gateway_cs = gateway.cs;
    contract->gateway_ip = gateway.ip;
    contract->gateway_ds = gateway.ds;
    contract->gateway_es = gateway.es;
    contract->gateway_ss = gateway.ss;
    contract->gateway_sp = gateway.sp;
    contract->gateway_eflags = gateway.eflags;
    memcpy(contract->gateway_gprs, gateway.gprs, sizeof(gateway.gprs));
    if (uc_mem_read(uc, k_gateway_base + k_gateway_offset, contract->gateway_bytes,
                    sizeof(contract->gateway_bytes)) == UC_ERR_OK)
      contract->gateway_bytes_read = 1;
    return;
  }
  if (address == (uint64_t)k_client_code_base + (uint32_t)k_return_ip) {
    contract->client_return_hits++;
    /* This observer precedes the product hook, so it sees the lret landing on
     * the locked stack and then the resumed client instruction after the guest
     * stack-reload wrapper. Only the latter is guest execution. */
    DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(&session->context.run);
    if (transfer != NULL && transfer->return_reached) {
      const State returned = read_state(uc);
      contract->returned_ss = returned.ss;
      contract->returned_sp = returned.sp;
      contract->returned_eflags = returned.eflags;
      memcpy(contract->returned_gprs, returned.gprs, sizeof(returned.gprs));
    }
    if (session->restart_after_return && transfer != NULL && transfer->return_reached &&
        !contract->restart_seen) {
      contract->restart_seen = 1;
      session->context.run.resume_address =
        ((uint32_t)get_reg16(uc, UC_X86_REG_CS) << 4) + get_reg16(uc, UC_X86_REG_IP);
      session->context.run.use_resume_address = 1;
      uc_emu_stop(uc);
      return;
    }
  }
  const uint16_t second_fault_offset =
    (uint16_t)(k_second_fault_offset + (session->repeated_fault_les ? 3 : 0));
  if (session->repeated_fault && address == (uint64_t)k_client_code_base + second_fault_offset) {
    contract->second_fault_hits++;
    /* The first fetch is the lret landing before the return hook. The second
     * is the wrapper-restored attempt; a third identical fetch is Unicorn's
     * retry in place of a second hardware vector. */
    if (contract->second_fault_hits >= 3) uc_emu_stop(uc);
  }
  if (!contract->reached_entry && address == (uint64_t)k_handler_code_base + k_handler_offset) {
    const State entry = read_state(uc);
    contract->reached_entry = 1;
    contract->entry_hook_hits++;
    contract->entry_linear = address;
    contract->entry_cs = entry.cs;
    contract->entry_ip = entry.ip;
    contract->entry_ds = entry.ds;
    contract->entry_es = entry.es;
    contract->entry_ss = entry.ss;
    contract->entry_sp = entry.sp;
    contract->entry_eflags = entry.eflags;
    memcpy(contract->entry_gprs, entry.gprs, sizeof(entry.gprs));
  }
  if (session->make_fault_selector_present &&
      address == (uint64_t)k_handler_code_base + k_handler_offset) {
    uint8_t access = 0;
    if (uc_mem_read(uc, k_dpmi_ldt_address + k_api_slot + 5, &access, sizeof(access)) !=
          UC_ERR_OK ||
        uc_mem_write(uc, k_dpmi_ldt_address + k_api_slot + 5, &(uint8_t){(uint8_t)(access | 0x80u)},
                     sizeof(access)) != UC_ERR_OK ||
        !daze_flush_translation_cache(uc, &session->context.engine.metrics)) {
      contract->failed = 1;
      uc_emu_stop(uc);
    } else {
      contract->fault_selector_made_present = 1;
    }
  }
}

static int build_artifacts(const Session *session, DazeDpmiTransitionArtifacts *artifacts) {
  const DazeDpmiTransitionDescriptorAddition additions[] = {
    /* 16-bit DPMILOAD code at base 000108d0h, and therefore the handler. */
    {DAZE_DPMI_TRANSITION_GDT, k_handler_selector, k_handler_code_base, 0xffff, 0x9b, 0x00},
    /* 32-bit LDT system descriptor for base 007e0000h. */
    {DAZE_DPMI_TRANSITION_GDT, k_ldt_selector, k_dpmi_ldt_address, 0xffff, 0x82, 0x00},
    /* The host-owned gateway the product enters, with the same descriptor the
     * runtime publishes, so the writer resolves its base rather than deriving
     * one from the selector number. */
    {DAZE_DPMI_TRANSITION_GDT, k_dpmi_exception_gateway_selector, k_gateway_base, 0xffff, 0x9b,
     0x00},
    /* Host-owned locked stack: 16-bit data, byte granularity, 4 KiB. */
    {DAZE_DPMI_TRANSITION_GDT, k_locked_stack_selector, k_locked_stack_base, k_locked_stack_limit,
     0x92, 0x00},
    /* 16-bit host code: the far-return landing pad named by the frame. */
    {DAZE_DPMI_TRANSITION_GDT, k_host_code_selector, k_host_code_base, 0xffff, 0x9b, 0x00},
    /* 16-bit park for any vector the capture failed to intercept. */
    {DAZE_DPMI_TRANSITION_GDT, k_park_selector, k_park_base, 0xffff, 0x9b, 0x00},
    /* 16-bit client code at base 00061000h with the recorded 5540h limit. */
    {DAZE_DPMI_TRANSITION_LDT, k_client_code_slot, k_client_code_base, k_client_code_limit, 0x9a,
     0x00},
    /* The recorded non-present API code descriptor. A non-present GDT entry
     * raises #GP; the observed selector's TI bit is 1, so it lives in the LDT
     * and raises #NP. */
    {DAZE_DPMI_TRANSITION_LDT, k_api_slot, k_api_base, k_api_limit,
     session->present_far_call ? (uint8_t)(k_api_access | 0x80u) : k_api_access, 0x00},
    {DAZE_DPMI_TRANSITION_LDT, k_second_api_slot, k_second_api_base, k_second_api_limit,
     k_api_access, 0x00},
    /* 16-bit client data and stack at the recorded base; the limit is not
     * recorded and is modelled as 64 KiB. */
    {DAZE_DPMI_TRANSITION_LDT, k_client_data_slot, k_client_data_base, 0xffff, 0x93, 0x00},
  };
  const DazeDpmiTransitionArtifactInput input = {
    .client_ds = k_client_data_selector,
    .client_ss = k_client_data_selector,
    .return_ip = k_return_ip,
    .return_cs = k_return_cs,
    .psp_segment = k_psp_segment,
    .entry_segment = k_dpmi_entry_segment,
    .gdt_address = k_dpmi_gdt_address,
    .ldt_address = k_dpmi_ldt_address,
    .additions = additions,
    .addition_count = sizeof(additions) / sizeof(additions[0]),
  };
  return daze_dpmi_transition_artifacts_build(&input, artifacts);
}

static void print_descriptor(const char *label, const uint8_t *bytes) {
  fprintf(stderr,
          "  %-10s %02x %02x %02x %02x %02x %02x %02x %02x"
          "  base %08" PRIx32 " limit %04x present %u\n",
          label, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
          (uint32_t)bytes[2] | ((uint32_t)bytes[3] << 8) | ((uint32_t)bytes[4] << 16) |
            ((uint32_t)bytes[7] << 24),
          (uint32_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8)), (unsigned)(bytes[5] & 0x80u));
}

static int print_guest_descriptor(uc_engine *uc, const char *label, uint32_t address) {
  uint8_t bytes[8] = {0};
  if (uc_mem_read(uc, address, bytes, sizeof(bytes)) != UC_ERR_OK) return 0;
  print_descriptor(label, bytes);
  return 1;
}

static void print_frame(const Contract *contract) {
  fprintf(stderr, "  frame at %08" PRIx32 " =", contract->frame_linear);
  for (size_t index = 0; index < DAZE_DPMI_EXCEPTION_FRAME_SIZE; ++index)
    fprintf(stderr, " %02x", contract->frame[index]);
  fprintf(stderr, "\n");
}

/* Use a direct far return to exercise the production exception return;
 * negative classifier cases retain a parked handler. */
static uc_err write_handler_body(uc_engine *uc, const Session *session) {
  if (session->return_handler)
    return uc_mem_write(uc, k_handler_code_base + k_handler_offset, k_handler_return,
                        sizeof(k_handler_return));
  return uc_mem_write(uc, k_handler_code_base + k_handler_offset, k_park, sizeof(k_park));
}

/* Returns 0 if the synthetic machine cannot be built. */
static int run_session(Session *session, const char *label) {
  DazeDpmiTransitionArtifacts artifacts;
  if (!build_artifacts(session, &artifacts)) {
    fprintf(stderr, "exception-entry-transfer-contract: transition artifacts build failed\n");
    return 0;
  }
  uc_engine *uc = NULL;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK) {
    fprintf(stderr, "exception-entry-transfer-contract: uc_open failed\n");
    return 0;
  }
  Contract *const contract = &session->contract;
  contract->unexpected_vector = k_unexpected_vector;
  /* DPMILOAD's recorded 0203h set-exception-vector result. Without it there is
   * no installed client handler to reach. */
  if (!session->omit_installed_vector) {
    session->context.process.dpmi.exception_vector_segment[0x0b] = k_handler_selector;
    session->context.process.dpmi.exception_vector_offset[0x0b] = k_handler_offset;
  }
  uint8_t flags = 0;
  if (uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_gdt_address, artifacts.gdt, sizeof(artifacts.gdt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_ldt_address, artifacts.ldt, sizeof(artifacts.ldt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_gdtr_operand, artifacts.gdtr, sizeof(artifacts.gdtr)) != UC_ERR_OK ||
      uc_mem_write(uc, k_entry_address, k_preamble, sizeof(k_preamble)) != UC_ERR_OK ||
      uc_mem_write(uc, k_handler_code_base + k_bootstrap_offset, k_bootstrap,
                   sizeof(k_bootstrap)) != UC_ERR_OK ||
      write_handler_body(uc, session) != UC_ERR_OK || !build_idt(uc) ||
      !build_client_stub(uc, session) ||
      uc_mem_read(uc, k_dpmi_gdt_address + k_locked_stack_selector + 6, &flags, 1) != UC_ERR_OK) {
    fprintf(stderr, "exception-entry-transfer-contract: machine build failed\n");
    uc_close(uc);
    return 0;
  }
  contract->locked_stack_db = (uint8_t)((flags >> 4) & 1);

  uc_hook interrupt_hook = 0;
  uc_hook code_hook = 0;
  if (uc_hook_add(uc, &interrupt_hook, UC_HOOK_INTR, on_interrupt, session, 1, 0) != UC_ERR_OK ||
      uc_hook_add(uc, &code_hook, UC_HOOK_CODE, on_code, session, 1, 0) != UC_ERR_OK) {
    fprintf(stderr, "exception-entry-transfer-contract: hook setup failed\n");
    uc_close(uc);
    return 0;
  }
  if (label != NULL) {
    print_guest_descriptor(uc, "gdt[0008]", k_dpmi_gdt_address + k_handler_selector);
    print_guest_descriptor(uc, "gdt[0028]", k_dpmi_gdt_address + k_gateway_selector);
    print_guest_descriptor(uc, "gdt[0030]", k_dpmi_gdt_address + k_ldt_selector);
    print_guest_descriptor(uc, "gdt[0048]", k_dpmi_gdt_address + k_locked_stack_selector);
    print_guest_descriptor(uc, "gdt[0060]", k_dpmi_gdt_address + k_host_code_selector);
    print_guest_descriptor(uc, "ldt[00b0]", k_dpmi_ldt_address + k_client_code_slot);
    print_guest_descriptor(uc, "ldt[00d0]", k_dpmi_ldt_address + k_api_slot);
    print_guest_descriptor(uc, "ldt[0120]", k_dpmi_ldt_address + k_client_data_slot);
  }

  /* Follow backend_runner.c stop/resume ordering to test the published begin address. */
  uint64_t begin = k_entry_address;
  const int rounds = session->restart_after_return ? k_session_return_rounds + 1
                     : session->return_handler     ? k_session_return_rounds
                                                   : k_session_rounds;
  for (int round = 0; round < rounds; ++round) {
    session->context.run.stopped = 0;
    session->context.run.continue_run = 0;
    session->context.run.use_resume_address = 0;
    contract->emulation_runs++;
    const uc_err error = uc_emu_start(uc, begin, 0, 0, k_instruction_budget);
    if (error != UC_ERR_OK) {
      contract->failed = 1;
      break;
    }
    /* Follow the production runner: termination precedes explicit re-entry. */
    if (session->context.run.terminated) break;
    if (session->context.run.use_resume_address) {
      begin = session->context.run.resume_address;
      contract->resume_armed = 1;
      contract->resume_address = session->context.run.resume_address;
      continue;
    }
    if (session->context.run.continue_run) continue;
    if (session->context.run.stopped) {
      /* The runner would redispatch here. The product's own dispatcher is
       * called so the classification is the product's, and the stale `0Bh`
       * must not be re-entered. */
      contract->stale_dispatches++;
      (void)daze_dispatch_interrupt(uc, session->context.run.interrupt_number,
                                    &session->context.engine, &session->context.run,
                                    &session->context.process, &session->files);
    }
    break;
  }
  DazeDpmiExceptionTransfer *const transfer = daze_dpmi_exception_active(&session->context.run);
  contract->transferred_still_armed = transfer != NULL && (transfer->armed || transfer->active);
  contract->return_reached = transfer != NULL && transfer->return_reached;
  contract->transferred = transfer != NULL && transfer->frame_linear != 0;
  if (contract->transferred) {
    contract->frame_linear = transfer->frame_linear;
    contract->entry_cs = transfer->entry_cs;
    contract->entry_ip = transfer->entry_ip;
    contract->entry_ds = transfer->entry_ds;
    contract->entry_es = transfer->entry_es;
    contract->entry_ss = transfer->entry_ss;
    contract->entry_sp = transfer->entry_sp;
    contract->entry_eflags = transfer->entry_eflags;
    memcpy(contract->frame, transfer->frame, sizeof(contract->frame));
  }
  /* Mirror production teardown (run_unicorn_loop): release any delivery still
   * active — including its heap hook bundle — before closing the engine. */
  daze_dpmi_exception_transfer_disarm(uc, &session->context.run);
  uc_close(uc);
  return 1;
}

static int run_production_mode(void) {
  Session session;
  memset(&session, 0, sizeof(session));
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  if (!run_session(&session, "return")) return 1;
  Contract *const contract = &session.contract;

  check(contract, contract->unexpected_vector == k_unexpected_vector,
        "unexpected CPU exception or park entry");
  check(contract, contract->captured, "vector 0Bh must be delivered at 00b4:%04x",
        k_client_fault_offset);
  if (contract->captured) {
    print_frame(contract);
    check(contract, contract->classified, "the product classifier must accept this boundary");
    check(contract, contract->error_code == k_api_selector, "error code %04x != %04x",
          contract->error_code, k_api_selector);
    check(contract, contract->fault_cs == k_client_code_selector, "fault CS %04x != %04x",
          contract->fault_cs, k_client_code_selector);
    check(contract, contract->fault_ip == k_client_fault_offset, "fault IP %04x != %04x",
          contract->fault_ip, k_client_fault_offset);
    check(contract, contract->fault_linear == (uint32_t)k_client_code_base + k_client_fault_offset,
          "fault linear %08" PRIx32 " must be the client code base plus the faulting offset",
          contract->fault_linear);
    check(contract,
          contract->fault_ds == k_client_data_selector &&
            contract->fault_es == k_client_data_selector &&
            contract->fault_ss == k_client_data_selector,
          "captured segments ds=%04x es=%04x ss=%04x", contract->fault_ds, contract->fault_es,
          contract->fault_ss);
    check(contract, contract->fault_sp == k_client_entry_sp, "captured SP %04x != %04x",
          contract->fault_sp, k_client_entry_sp);
    check(contract, memcmp(contract->fault_gprs, k_client_gprs, sizeof(contract->fault_gprs)) == 0,
          "captured GPRs must be the recorded client state");
    check(contract, (contract->fault_eflags & 0xffffu) == k_client_flags,
          "captured flags %04x != %04x", (unsigned)(contract->fault_eflags & 0xffffu),
          k_client_flags);
    check(contract, (contract->fault_eflags & 0x0200u) != 0, "captured flags must have IF set");
  }

  /* The transfer stopped, and the loop re-entered at the address it published.
   * That address is the established `(selector << 4) + offset` form, not the
   * gateway's linear address, which is what makes the fetch land on the
   * gateway. */
  check(contract, contract->resume_armed, "the transfer must publish a resume address");

  /* The gateway is entered at its own selector and offset, from the published
   * resume address, with the client's segments, stack and flags intact: the
   * route has not run yet, so `cli` has not executed either. */
  check(contract, contract->reached_gateway,
        "the resume address must reach the gateway's first byte");
  if (contract->reached_gateway) {
    check(contract,
          contract->gateway_cs == k_gateway_selector && contract->gateway_ip == k_gateway_offset,
          "gateway CS:IP %04x:%04x != %04x:%04x", contract->gateway_cs, contract->gateway_ip,
          k_gateway_selector, k_gateway_offset);
    check(contract,
          contract->gateway_ss == k_client_data_selector &&
            contract->gateway_sp == k_client_entry_sp,
          "gateway SS:SP %04x:%04x != %04x:%04x", contract->gateway_ss, contract->gateway_sp,
          k_client_data_selector, k_client_entry_sp);
    check(contract,
          contract->gateway_ds == k_client_data_selector &&
            contract->gateway_es == k_client_data_selector,
          "gateway DS/ES %04x/%04x must still be the client data segment, whose base is not the "
          "gateway's",
          contract->gateway_ds, contract->gateway_es);
    check(contract,
          memcmp(contract->gateway_gprs, contract->fault_gprs, sizeof(contract->gateway_gprs)) == 0,
          "the transfer must not change any general register");
    check(contract, (contract->gateway_eflags & 0x0200u) != 0,
          "IF must still be set when the gateway's first instruction is fetched");
    check(contract,
          contract->gateway_bytes_read &&
            memcmp(contract->gateway_bytes, k_gateway_route, sizeof(k_gateway_route)) == 0,
          "the gateway bytes must be the audited route with a filler after each instruction");
  }

  /* Observe handler entry before its first instruction executes: the gateway
   * has loaded the locked stack and cleared IF while preserving client DS/ES
   * and GPRs. */
  check(contract, contract->transferred, "the transfer must arm the entry hook");
  check(contract, contract->reached_entry, "the gateway must reach the handler's first byte");
  if (contract->transferred && contract->reached_entry) {
    check(contract,
          contract->entry_cs == k_handler_selector && contract->entry_ip == k_handler_offset,
          "entry CS:IP %04x:%04x != %04x:%04x", contract->entry_cs, contract->entry_ip,
          k_handler_selector, k_handler_offset);
    check(contract, contract->entry_linear == (uint64_t)k_handler_code_base + k_handler_offset,
          "entry linear %08" PRIx64
          " must be the handler descriptor's base plus the handler offset",
          contract->entry_linear);
    check(contract,
          contract->entry_ss == k_locked_stack_selector && contract->entry_sp == k_locked_stack_sp,
          "entry SS:SP %04x:%04x != %04x:%04x", contract->entry_ss, contract->entry_sp,
          k_locked_stack_selector, k_locked_stack_sp);
    check(contract,
          contract->entry_ds == k_client_data_selector &&
            contract->entry_es == k_client_data_selector,
          "entry DS/ES %04x/%04x must stay the captured values", contract->entry_ds,
          contract->entry_es);
    check(contract,
          memcmp(contract->entry_gprs, contract->fault_gprs, sizeof(contract->entry_gprs)) == 0,
          "entry GPRs %04x %04x %04x %04x %04x %04x %04x must equal the captured GPRs %04x %04x "
          "%04x %04x %04x %04x %04x, so the AX save/restore round trip",
          contract->entry_gprs[0], contract->entry_gprs[1], contract->entry_gprs[2],
          contract->entry_gprs[3], contract->entry_gprs[4], contract->entry_gprs[5],
          contract->entry_gprs[6], contract->fault_gprs[0], contract->fault_gprs[1],
          contract->fault_gprs[2], contract->fault_gprs[3], contract->fault_gprs[4],
          contract->fault_gprs[5], contract->fault_gprs[6]);
    check(contract, (contract->entry_eflags & 0x0200u) == 0,
          "IF must be clear at entry (%08" PRIx32 ")", contract->entry_eflags);
    check(contract, (contract->entry_eflags & 0x0002u) != 0, "bit 1 must stay set at entry");
    check(contract, contract->frame_linear == (uint32_t)k_locked_stack_base + k_locked_stack_sp,
          "frame address %08" PRIx32 " unexpected", contract->frame_linear);

    DazeDpmiExceptionFrameInput input;
    memset(&input, 0, sizeof(input));
    input.frame.return_ip = k_return_ip;
    input.frame.return_cs = k_return_cs;
    input.frame.error_code = contract->error_code;
    input.frame.fault_ip = contract->fault_ip;
    input.frame.fault_cs = contract->fault_cs;
    input.frame.flags = (uint16_t)contract->fault_eflags;
    input.frame.stack_pointer = contract->fault_sp;
    input.frame.stack_segment = contract->fault_ss;
    input.locked_stack_base = k_locked_stack_base;
    input.locked_stack_sp = k_locked_stack_sp;
    input.guest_range_base = 0;
    input.guest_range_limit = k_memory_size - 1;
    uint32_t expected_linear = 0;
    uint8_t expected[DAZE_DPMI_EXCEPTION_FRAME_SIZE] = {0};
    check(contract, daze_dpmi_exception_frame_build(&input, &expected_linear, expected),
          "the pure helper must rebuild the entry frame");
    check(contract, expected_linear == contract->frame_linear,
          "the rebuilt frame address %08" PRIx32 " differs", expected_linear);
    check(contract, memcmp(contract->frame, expected, sizeof(expected)) == 0,
          "the entry frame must equal the pure helper output");
    check(contract,
          expected[0] == 0x5f && expected[1] == 0x01 && expected[2] == 0xb4 &&
            expected[3] == 0x00 && expected[4] == 0xd4 && expected[5] == 0x00 &&
            expected[6] == 0x5a && expected[7] == 0x01 && expected[8] == 0xb4 &&
            expected[9] == 0x00 && expected[10] == 0x82 && expected[11] == 0x02 &&
            expected[12] == 0xb0 && expected[13] == 0xff && expected[14] == 0x24 &&
            expected[15] == 0x01,
          "the frame words must be Return IP/CS, Err Code, IP, CS, Flags, SP, SS");
  }

  check(contract, contract->locked_stack_db == 0, "the locked stack must keep a 16-bit SP (D/B=0)");

  check(contract, session.context.run.interrupt_number == 0x0b,
        "the intercepted vector must remain available for classification checks (0%02x)",
        session.context.run.interrupt_number);
  check(contract, contract->entry_hook_hits == 1, "the one-shot entry hook must fire once, not %u",
        contract->entry_hook_hits);
  check(contract, contract->return_reached,
        "the handler far return must reach the exact exception-return hook");
  check(contract,
        contract->returned_ss == k_client_data_selector &&
          contract->returned_sp == k_client_entry_sp,
        "client continuation SS:SP %04x:%04x != %04x:%04x", contract->returned_ss,
        contract->returned_sp, k_client_data_selector, k_client_entry_sp);
  check(contract, (contract->returned_eflags & 0xffffu) == k_client_flags,
        "client continuation FLAGS %04x != %04x", (unsigned)(contract->returned_eflags & 0xffffu),
        k_client_flags);
  check(contract, contract->stale_dispatches == 0,
        "the stale 0Bh must not be redispatched, but %u dispatches were attempted",
        contract->stale_dispatches);
  check(contract, !contract->transferred_still_armed,
        "the one-shot hooks and transfer state must be disposed after the return");

  /* Rejected boundaries must leave gateway state untouched. */
  struct {
    const char *label;
    int software_int;
    int omit_vector;
    int present_far_call;
  } const negatives[] = {
    {"software int 0Bh", 1, 0, 0},
    {"absent 0203h vector", 0, 1, 0},
    {"present far-call selector", 0, 0, 1},
  };
  for (size_t index = 0; index < sizeof(negatives) / sizeof(negatives[0]); ++index) {
    Session negative;
    memset(&negative, 0, sizeof(negative));
    negative.use_software_int = negatives[index].software_int;
    negative.omit_installed_vector = negatives[index].omit_vector;
    negative.present_far_call = negatives[index].present_far_call;
    if (!run_session(&negative, NULL)) return 1;
    Contract *const rejected = &negative.contract;
    fprintf(stderr, "  negative: %-26s vector=%u classified=%u gateway=%u entry=%u\n",
            negatives[index].label, (unsigned)negative.delivered_vector,
            (unsigned)rejected->classified, (unsigned)rejected->reached_gateway,
            (unsigned)rejected->reached_entry);
    check(contract, rejected->classified == 0, "%s must not activate the classifier",
          negatives[index].label);
    check(contract, rejected->reached_gateway == 0, "%s must not enter the gateway",
          negatives[index].label);
    check(contract, rejected->reached_entry == 0, "%s must not reach the handler",
          negatives[index].label);
    check(contract, rejected->transferred == 0, "%s must not arm the entry hook",
          negatives[index].label);
    if (negatives[index].software_int) {
      check(contract, negative.delivered_vector == 1, "the software int must still deliver 0Bh");
    }
    if (negatives[index].present_far_call) {
      check(contract, negative.delivered_vector == 0,
            "a present far-call selector must not raise a vector at all");
    }
  }

  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* A synthetic handler returns through the frame words; the production hook
 * must reload the interrupted stack before the client continuation fetches. */
static int run_return_mode(void) {
  Session session;
  memset(&session, 0, sizeof(session));
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  if (!run_session(&session, "return")) return 1;
  Contract *const contract = &session.contract;
  check(contract, contract->captured && contract->classified && contract->transferred,
        "the return witness must first reach the ordinary exception transfer");
  check(contract, contract->return_reached,
        "the one-shot exception-return hook must recognise the frame return address");
  check(contract, contract->client_return_hits == 2,
        "the observer must see the lret landing and one resumed fetch, not %u hits",
        contract->client_return_hits);
  check(contract,
        contract->returned_ss == k_client_data_selector &&
          contract->returned_sp == k_client_entry_sp,
        "client continuation SS:SP %04x:%04x != %04x:%04x", contract->returned_ss,
        contract->returned_sp, k_client_data_selector, k_client_entry_sp);
  check(contract, (contract->returned_eflags & 0xffffu) == k_client_flags,
        "client continuation FLAGS %04x != %04x", (unsigned)(contract->returned_eflags & 0xffffu),
        k_client_flags);
  check(contract,
        memcmp(contract->returned_gprs, contract->entry_gprs, sizeof(contract->returned_gprs)) == 0,
        "the return wrapper must preserve the handler's GPR result");
  check(contract, !contract->transferred_still_armed,
        "both exception-transfer hooks must be disposed after the return");
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* Changing only the descriptor present bit must select fault-IP retry rather
 * than the ordinary successor after handler return. */
static int run_retry_present_mode(void) {
  Session session = {0};
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  session.make_fault_selector_present = 1;
  if (!run_session(&session, "retry-present")) return 1;
  Contract *const contract = &session.contract;
  check(contract, contract->captured && contract->classified && contract->return_reached,
        "the resolved-selector witness must complete the return transition");
  check(contract, contract->fault_selector_made_present,
        "the synthetic handler must make the fault selector present before its lret");
  check(contract, contract->retried_fault_hits == 1,
        "a handler that makes the selector present must resume at the fault IP once, not %u times",
        contract->retried_fault_hits);
  check(contract, contract->client_return_hits == 1,
        "the lret may land once on the saved successor, but guest execution must not resume there");
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* Observation-only mode: after a handler return and stack reload, Unicorn
 * retries the second non-present call without reporting another #NP vector. */
static int run_repeated_fault_mode(void) {
  Session session;
  memset(&session, 0, sizeof(session));
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  session.repeated_fault = 1;
  if (!run_session(&session, "repeated-fault")) return 1;
  Contract *const contract = &session.contract;
  check(contract, contract->captured && contract->classified && contract->return_reached,
        "the first non-present call must complete the return transition");
  check(contract, session.delivered_vector == 1,
        "Unicorn must report only the first #NP, but reported %d vectors",
        session.delivered_vector);
  check(contract, contract->second_fault_hits >= 3,
        "the second non-present call must retry without a vector, but fetched %u times",
        contract->second_fault_hits);
  check(contract,
        contract->returned_ss == k_client_data_selector &&
          contract->returned_sp == k_client_entry_sp,
        "the retry must occur after the client stack reload, not on the locked stack");
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* Omit handler returns to isolate nested delivery ownership: both records must
 * remain live in separate locked-stack slots with their frame bytes intact. */
static int run_nested_delivery_mode(void) {
  Session session = {0};
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  DazeDpmiTransitionArtifacts artifacts;
  if (!build_artifacts(&session, &artifacts)) return 1;
  uc_engine *uc = NULL;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK) return 1;
  Contract *const contract = &session.contract;
  session.context.process.dpmi.exception_vector_segment[0x0b] = k_handler_selector;
  session.context.process.dpmi.exception_vector_offset[0x0b] = k_handler_offset;
  if (uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_gdt_address, artifacts.gdt, sizeof(artifacts.gdt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_ldt_address, artifacts.ldt, sizeof(artifacts.ldt)) != UC_ERR_OK) {
    uc_close(uc);
    return 1;
  }
  const DazeDpmiExceptionFault faults[] = {
    {.fault_ip = k_client_fault_offset,
     .error_code = k_api_selector,
     .fault_cs = k_client_code_selector,
     .fault_ss = k_client_data_selector,
     .fault_sp = k_client_entry_sp,
     .fault_ds = k_client_data_selector,
     .fault_es = k_client_data_selector,
     .instruction_size = k_far_call_size,
     .eflags = k_client_flags},
    {.fault_ip = k_second_fault_offset,
     .error_code = k_second_api_selector,
     .fault_cs = k_client_code_selector,
     .fault_ss = k_client_data_selector,
     .fault_sp = k_client_entry_sp,
     .fault_ds = k_client_data_selector,
     .fault_es = k_client_data_selector,
     .instruction_size = k_far_call_size,
     .eflags = k_client_flags},
  };
  if (!daze_dpmi_exception_transfer(uc, &session.context.engine, &session.context.run,
                                    &session.context.process.dpmi, &faults[0]) ||
      !daze_dpmi_exception_transfer(uc, &session.context.engine, &session.context.run,
                                    &session.context.process.dpmi, &faults[1])) {
    contract->failed = 1;
  }
  const DazeDpmiExceptionTransfer *const parent =
    daze_dpmi_exception_record(&session.context.run, 0);
  const DazeDpmiExceptionTransfer *const child =
    daze_dpmi_exception_record(&session.context.run, 1);
  if (parent != NULL && child != NULL &&
      uc_mem_read(uc, parent->frame_linear, contract->nested_parent_frame,
                  sizeof(contract->nested_parent_frame)) == UC_ERR_OK &&
      uc_mem_read(uc, child->frame_linear, contract->nested_child_frame,
                  sizeof(contract->nested_child_frame)) == UC_ERR_OK) {
    contract->nested_depth = session.context.run.exception_delivery_stack.depth;
    contract->nested_parent_frame_linear = parent->frame_linear;
    contract->nested_child_frame_linear = child->frame_linear;
  } else {
    contract->failed = 1;
  }
  check(contract, contract->nested_depth == 2,
        "two transfers must retain parent and child deliveries, depth=%u", contract->nested_depth);
  check(contract, contract->nested_parent_frame_linear != contract->nested_child_frame_linear,
        "parent and child deliveries must use distinct frame slots");
  check(contract,
        contract->nested_parent_frame_linear + DAZE_DPMI_EXCEPTION_FRAME_SIZE <=
            contract->nested_child_frame_linear ||
          contract->nested_child_frame_linear + DAZE_DPMI_EXCEPTION_FRAME_SIZE <=
            contract->nested_parent_frame_linear,
        "parent and child frame slots must not overlap");
  check(contract,
        memcmp(contract->nested_parent_frame,
               session.context.run.exception_delivery_stack.records[0].frame,
               sizeof(contract->nested_parent_frame)) == 0,
        "the parent frame must remain byte-identical while the child is active");
  check(contract,
        memcmp(contract->nested_child_frame,
               session.context.run.exception_delivery_stack.records[1].frame,
               sizeof(contract->nested_child_frame)) == 0,
        "the child frame must remain byte-identical at child entry");
  const uc_hook parent_entry_hook = session.context.run.exception_delivery_stack.records[0].hook;
  check(contract, daze_dpmi_exception_transfer_dispose_active(uc, &session.context.run),
        "disposing the active child record must succeed");
  check(contract, session.context.run.exception_delivery_stack.depth == 1,
        "disposing the child must restore the parent as active");
  check(contract,
        session.context.run.exception_delivery_stack.records[0].armed &&
          session.context.run.exception_delivery_stack.records[0].hook == parent_entry_hook,
        "disposing a child must not delete the parent's entry hook");
  daze_dpmi_exception_transfer_disarm(uc, &session.context.run);
  uc_close(uc);
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

static int run_repeated_fault_restart_mode(void) {
  Session session = {0};
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  session.repeated_fault = 1;
  session.restart_after_return = 1;
  if (!run_session(&session, NULL)) return 1;
  check(&session.contract, session.contract.restart_seen, "restart did not reach returned IP");
  check(&session.contract, session.contract.second_fault_vectors == 1, "second #NP vectors=%u",
        session.contract.second_fault_vectors);
  printf("exception-entry-transfer-contract: %s\n", session.contract.failed ? "FAILED" : "passed");
  return session.contract.failed;
}

static int run_repeated_fault_les_mode(void) {
  Session session = {0};
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  session.return_handler = 1;
  session.repeated_fault = 1;
  session.repeated_fault_les = 1;
  if (!run_session(&session, "repeated-fault-les")) return 1;
  Contract *const contract = &session.contract;
  check(contract, contract->captured && contract->classified && contract->return_reached,
        "the first non-present call must complete the return transition");
  check(contract, session.delivered_vector == 1,
        "Unicorn must report only the first #NP, but reported %d vectors",
        session.delivered_vector);
  check(contract, contract->second_fault_hits >= 3,
        "LES must retry without a vector, but fetched %u times", contract->second_fault_hits);
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* DPMILOAD's post-EOF path returns with a 16-bit LRET whose stack frame names
 * another non-present overlay selector. Unicorn retries that return without a
 * second interrupt vector, so the existing successor hook must classify the
 * exact stack-derived #NP boundary before the instruction retires. */
static int run_lret_classification_mode(void) {
  Session session = {0};
  daze_dosfs_file_service_init(&session.files, &session.mounts, &session.handles);
  DazeDpmiTransitionArtifacts artifacts;
  if (!build_artifacts(&session, &artifacts)) return 1;
  uc_engine *uc = NULL;
  if (uc_open(UC_ARCH_X86, UC_MODE_16, &uc) != UC_ERR_OK) return 1;
  Contract *const contract = &session.contract;
  session.context.process.dpmi.exception_vector_segment[0x0b] = k_handler_selector;
  session.context.process.dpmi.exception_vector_offset[0x0b] = k_handler_offset;
  const uint8_t lret[] = {0xcb, 0x06, 0x00}; /* retf faults here; trailing context */
  const uint8_t frame[4] = {0x93, 0x02, (uint8_t)k_second_api_selector,
                            (uint8_t)(k_second_api_selector >> 8)};
  uint16_t cs = k_client_code_selector;
  uint16_t ip = k_client_fault_offset;
  uint16_t ss = k_client_data_selector;
  uint16_t sp = k_client_entry_sp;
  uint32_t cr0 = 0x11;
  if (uc_mem_map(uc, 0, k_memory_size, UC_PROT_ALL) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_gdt_address, artifacts.gdt, sizeof(artifacts.gdt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_dpmi_ldt_address, artifacts.ldt, sizeof(artifacts.ldt)) != UC_ERR_OK ||
      uc_mem_write(uc, k_client_code_base + k_client_fault_offset, lret, sizeof(lret)) !=
        UC_ERR_OK ||
      uc_mem_write(uc, k_client_data_base + k_client_entry_sp, frame, sizeof(frame)) != UC_ERR_OK ||
      uc_reg_write(uc, UC_X86_REG_CS, &cs) != UC_ERR_OK ||
      uc_reg_write(uc, UC_X86_REG_IP, &ip) != UC_ERR_OK ||
      uc_reg_write(uc, UC_X86_REG_SS, &ss) != UC_ERR_OK ||
      uc_reg_write(uc, UC_X86_REG_SP, &sp) != UC_ERR_OK ||
      uc_reg_write(uc, UC_X86_REG_CR0, &cr0) != UC_ERR_OK) {
    uc_close(uc);
    return 1;
  }
  DazeDpmiExceptionFault fault;
  memset(&fault, 0, sizeof(fault));
  check(contract, daze_dpmi_exception_classify(uc, &session.context.process.dpmi, &fault),
        "the non-present LRET target must classify");
  check(contract,
        fault.fault_cs == k_client_code_selector && fault.fault_ip == k_client_fault_offset,
        "LRET fault location %04x:%04x", fault.fault_cs, fault.fault_ip);
  check(contract, fault.fault_ss == k_client_data_selector && fault.fault_sp == k_client_entry_sp,
        "LRET stack %04x:%04x", fault.fault_ss, fault.fault_sp);
  check(contract, fault.error_code == k_second_api_selector && fault.instruction_size == 1,
        "LRET error selector %04x, size %u", fault.error_code, fault.instruction_size);
  const uint8_t opcode = 0xca;
  check(contract,
        uc_mem_write(uc, k_client_code_base + k_client_fault_offset, &opcode, sizeof(opcode)) ==
            UC_ERR_OK &&
          daze_dpmi_exception_classify(uc, &session.context.process.dpmi, &fault),
        "the non-present RETF 6 target must classify");
  check(contract,
        fault.error_code == k_second_api_selector && fault.instruction_size == 3 &&
          fault.fault_sp == k_client_entry_sp,
        "RETF 6 must retain its original stack and three-byte instruction size");
  uc_close(uc);
  printf("exception-entry-transfer-contract: %s\n", contract->failed ? "FAILED" : "passed");
  return contract->failed;
}

/* Test-only mode selection; no runtime diagnostic gate is required. */
int main(void) {
  const int failed =
    getenv("DAZE_DPMI_EXCEPTION_NESTED_DELIVERY") != NULL ? run_nested_delivery_mode()
    : getenv("DAZE_DPMI_EXCEPTION_REPEATED_FAULT_RESTART") != NULL
      ? run_repeated_fault_restart_mode()
    : getenv("DAZE_DPMI_EXCEPTION_LRET") != NULL                ? run_lret_classification_mode()
    : getenv("DAZE_DPMI_EXCEPTION_REPEATED_FAULT_LES") != NULL  ? run_repeated_fault_les_mode()
    : getenv("DAZE_DPMI_EXCEPTION_REPEATED_FAULT") != NULL      ? run_repeated_fault_mode()
    : getenv("DAZE_DPMI_EXCEPTION_RETRY_PRESENT") != NULL       ? run_retry_present_mode()
    : getenv("DAZE_DPMI_EXCEPTION_PRODUCTION_CONTRACT") != NULL ? run_production_mode()
                                                                : run_return_mode();
  return failed;
}
