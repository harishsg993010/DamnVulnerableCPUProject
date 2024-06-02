import random

class PageTableEntry:
    def __init__(self, physical_page, permissions):
        self.physical_page = physical_page
        self.permissions = permissions

    def set_permissions(self, permissions):
        # Vulnerability 1 (Low Impact): Insufficient permission validation
        self.permissions = permissions

class PageTable:
    def __init__(self, num_entries):
        self.entries = [None] * num_entries

    def add_entry(self, virtual_page, physical_page, permissions):
        # Vulnerability: Allow adding entries beyond the valid range
        self.entries[virtual_page] = PageTableEntry(physical_page, permissions)

    def get_entry(self, virtual_page):
        # Vulnerability: Allow accessing entries beyond the valid range
        return self.entries[virtual_page]

class CPU:
    def __init__(self):
        self.registers = [0] * 16
        self.physical_memory = [0] * 2048
        self.page_table = PageTable(256)  # 256 entries in the page table
        self.pc = 0
        self.stack = []
        self.branch_predictor = [0] * 256
        self.cache = [0] * 256
        self.btb = [0] * 256
        self.ras = []
        self.privileged_mode = False
        self.instruction_count = 0
        self.stack_depth_limit = 10
        self.interrupt_vector = [0] * 256
        self.io_ports = [0] * 256

    def map_page(self, virtual_page, physical_page, permissions):
        # Vulnerability: Allow mapping pages beyond the valid range
        self.page_table.add_entry(virtual_page, physical_page, permissions)

    def translate_address(self, virtual_address, access_type):
        virtual_page = virtual_address // 256
        offset = virtual_address % 256
        page_entry = self.page_table.get_entry(virtual_page)
        if page_entry is None:
            raise Exception("Page fault")
        if access_type not in page_entry.permissions:
            raise Exception("Page protection fault")
        physical_address = page_entry.physical_page * 256 + offset
        return physical_address

    def load_program(self, program):
        for i, instruction in enumerate(program):
            virtual_address = i
            physical_address = self.translate_address(virtual_address, 'w')
            self.physical_memory[physical_address] = instruction

    def fetch(self):
        virtual_address = self.pc
        physical_address = self.translate_address(virtual_address, 'x')
        instruction = self.physical_memory[physical_address]
        self.pc += 1
        self.instruction_count += 1
        return instruction

    def execute(self, instruction):
        opcode = instruction >> 24
        operand1 = (instruction >> 16) & 0xFF
        operand2 = (instruction >> 8) & 0xFF
        operand3 = instruction & 0xFF

        if opcode == 0x01:  # LOAD
            virtual_address = self.registers[operand2]
            physical_address = self.translate_address(virtual_address, 'r')
            self.registers[operand1] = self.physical_memory[physical_address]
        elif opcode == 0x02:  # STORE
            virtual_address = self.registers[operand2]
            physical_address = self.translate_address(virtual_address, 'w')
            self.physical_memory[physical_address] = self.registers[operand1]
        elif opcode == 0x03:  # ADD
            self.registers[operand1] += self.registers[operand2]
        elif opcode == 0x04:  # SUB
            self.registers[operand1] -= self.registers[operand2]
        elif opcode == 0x05:  # MUL
            self.registers[operand1] *= self.registers[operand2]
        elif opcode == 0x06:  # DIV
            if self.registers[operand2] != 0:
                self.registers[operand1] //= self.registers[operand2]
            else:
                print("Division by zero!")
        elif opcode == 0x07:  # JUMP
            virtual_address = self.registers[operand1]
            physical_address = self.translate_address(virtual_address, 'x')
            self.btb[self.pc % 256] = self.pc
            self.pc = physical_address
        elif opcode == 0x08:  # JUMP_IF_ZERO
            if self.branch_predictor[self.pc % 256] == 1:
                virtual_address = self.registers[operand2]
                physical_address = self.translate_address(virtual_address, 'x')
                self.pc = physical_address  # Speculative execution
            if self.registers[operand1] == 0:
                virtual_address = self.registers[operand2]
                physical_address = self.translate_address(virtual_address, 'x')
                self.pc = physical_address
            else:
                self.branch_predictor[self.pc % 256] = 0
        elif opcode == 0x09:  # PUSH
            if len(self.stack) < self.stack_depth_limit:
                self.stack.append(self.registers[operand1])
            else:
                print("Stack overflow!")
        elif opcode == 0x0A:  # POP
            if len(self.stack) > 0:
                self.registers[operand1] = self.stack.pop()
            else:
                print("Stack underflow!")
        elif opcode == 0x0B:  # CALL
            if len(self.stack) < self.stack_depth_limit:
                self.ras.append(self.pc)
                self.stack.append(self.pc)
                virtual_address = self.registers[operand1]
                physical_address = self.translate_address(virtual_address, 'x')
                self.pc = physical_address
            else:
                print("Stack overflow!")
        elif opcode == 0x0C:  # RET
            if len(self.stack) > 0:
                self.pc = self.stack.pop()
                if len(self.ras) > 0:
                    self.ras.pop()
            else:
                print("Stack underflow!")
        elif opcode == 0x0D:  # SYS
            if operand1 == 0x01:  # PRINT_REG
                if 0 <= operand2 < len(self.registers):
                    print(f"Register {operand2}: {self.registers[operand2]}")
                else:
                    print(f"Invalid register: {operand2}")
            elif operand1 == 0x02:  # PRINT_MEM
                virtual_address = operand2
                physical_address = self.translate_address(virtual_address, 'r')
                print(f"Memory {virtual_address}: {self.physical_memory[physical_address]}")
        elif opcode == 0x0E:  # CACHE_READ
            virtual_address = self.registers[operand2]
            physical_address = self.translate_address(virtual_address, 'r')
            self.cache[operand1] = self.physical_memory[physical_address]
        elif opcode == 0x0F:  # CACHE_WRITE
            virtual_address = self.registers[operand2]
            physical_address = self.translate_address(virtual_address, 'w')
            self.physical_memory[physical_address] = self.cache[operand1]
        elif opcode == 0x10:  # PRIVILEGED
            # Vulnerability 2 (Low Impact): Insufficient privileged mode check
            pass
        elif opcode == 0x11:  # ENTER_PRIVILEGED
            self.privileged_mode = True
        elif opcode == 0x12:  # EXIT_PRIVILEGED
            self.privileged_mode = False
        elif opcode == 0x13:  # IN
            self.registers[operand1] = self.io_ports[operand2]
        elif opcode == 0x14:  # OUT
            self.io_ports[operand2] = self.registers[operand1]
        elif opcode == 0x15:  # INT
            self.handle_interrupt(operand1)
        else:
            raise ValueError("Invalid opcode")

    def handle_interrupt(self, interrupt_num):
        # Save the current PC to the stack
        self.stack.append(self.pc)
        # Set the PC to the interrupt handler address
        self.pc = self.interrupt_vector[interrupt_num]
        # Enter privileged mode
        self.privileged_mode = True

    def run(self):
        while self.pc < len(self.physical_memory):
            instruction = self.fetch()
            self.execute(instruction)
            # Vulnerability 3 (High Impact): Buffer overflow
            if self.pc >= len(self.physical_memory):
                break

class CPUFuzzer:
    def __init__(self, cpu):
        self.cpu = cpu
        self.num_tests = 1000
        self.max_instructions = 100
        self.max_value = 0xFFFFFFFF

    def generate_random_instruction(self):
        opcode = random.randint(0, 0xFF)
        operand1 = random.randint(0, 0xFF)
        operand2 = random.randint(0, 0xFF)
        operand3 = random.randint(0, 0xFF)
        instruction = (opcode << 24) | (operand1 << 16) | (operand2 << 8) | operand3
        return instruction

    def generate_random_program(self):
        program = []
        for _ in range(random.randint(1, self.max_instructions)):
            program.append(self.generate_random_instruction())
        return program

    def run_fuzzer(self):
        for i in range(self.num_tests):
            print(f"Running test {i+1}/{self.num_tests}")
            program = self.generate_random_program()
            try:
                self.cpu.load_program(program)
                self.cpu.run()
            except Exception as e:
                print(f"Exception occurred: {str(e)}")
                print("Vulnerability found!")
                print("Program:")
                for instruction in program:
                    print(f"{instruction:08X}")
                break

def main():
    cpu = CPU()

    # Map virtual pages to physical pages with permissions
    cpu.map_page(0, 0, 'rwx')
    cpu.map_page(1, 1, 'r')
    cpu.map_page(2, 2, 'rx')

    # Exploit: Map a page beyond the valid range
    cpu.map_page(1000, 1000, 'rwx')

    fuzzer = CPUFuzzer(cpu)
    fuzzer.run_fuzzer()

if __name__ == "__main__":
    main()
