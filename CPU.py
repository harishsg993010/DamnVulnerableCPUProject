import tkinter as tk
from tkinter import ttk, scrolledtext

class CPU:
    def __init__(self):
        self.registers = [0] * 8
        self.memory = [0] * 1024
        self.pc = 0
        self.stack = []
        self.branch_predictor = [0] * 256
        self.cache = [0] * 256
        self.btb = [0] * 256
        self.ras = []
        self.privileged_mode = False
        self.instruction_count = 0
        self.stack_depth_limit = 10
        self.memory_protection = [False] * 1024

    def load_program(self, program):
        for i, instruction in enumerate(program):
            if 0 <= i < len(self.memory) and not self.memory_protection[i]:
                self.memory[i] = instruction
            else:
                print(f"Invalid memory address or memory protection violation: {i}")

    def fetch(self):
        if 0 <= self.pc < len(self.memory) and not self.memory_protection[self.pc]:
            instruction = self.memory[self.pc]
            self.pc += 1
            self.instruction_count += 1
            return instruction
        else:
            print(f"Invalid PC value or memory protection violation: {self.pc}")
            return 0

    def execute(self, instruction):
        opcode = instruction >> 24
        operand1 = (instruction >> 16) & 0xFF
        operand2 = (instruction >> 8) & 0xFF
        operand3 = instruction & 0xFF

        if opcode == 0x01:  # LOAD
            if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                self.registers[operand1] = self.memory[self.registers[operand2]]
            else:
                print(f"Invalid memory address or memory protection violation: {self.registers[operand2]}")
        elif opcode == 0x02:  # STORE
            if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                self.memory[self.registers[operand2]] = self.registers[operand1]
            else:
                print(f"Invalid memory address or memory protection violation: {self.registers[operand2]}")
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
            if 0 <= self.registers[operand1] < len(self.memory) and not self.memory_protection[self.registers[operand1]]:
                self.btb[self.pc % 256] = self.pc
                self.pc = self.registers[operand1]
            else:
                print(f"Invalid jump address or memory protection violation: {self.registers[operand1]}")
        elif opcode == 0x08:  # JUMP_IF_ZERO
            if self.branch_predictor[self.pc % 256] == 1:
                if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                    self.pc = self.registers[operand2]  # Speculative execution
                else:
                    print(f"Invalid jump address or memory protection violation: {self.registers[operand2]}")
            if self.registers[operand1] == 0:
                if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                    self.pc = self.registers[operand2]
                else:
                    print(f"Invalid jump address or memory protection violation: {self.registers[operand2]}")
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
                if 0 <= self.registers[operand1] < len(self.memory) and not self.memory_protection[self.registers[operand1]]:
                    self.pc = self.registers[operand1]
                else:
                    print(f"Invalid call address or memory protection violation: {self.registers[operand1]}")
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
                if 0 <= operand2 < len(self.memory) and not self.memory_protection[operand2]:
                    print(f"Memory {operand2}: {self.memory[operand2]}")
                else:
                    print(f"Invalid memory address or memory protection violation: {operand2}")
        elif opcode == 0x0E:  # CACHE_READ
            if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                self.cache[operand1] = self.memory[self.registers[operand2]]
            else:
                print(f"Invalid memory address or memory protection violation: {self.registers[operand2]}")
        elif opcode == 0x0F:  # CACHE_WRITE
            if 0 <= self.registers[operand2] < len(self.memory) and not self.memory_protection[self.registers[operand2]]:
                self.memory[self.registers[operand2]] = self.cache[operand1]
            else:
                print(f"Invalid memory address or memory protection violation: {self.registers[operand2]}")
        elif opcode == 0x10:  # PRIVILEGED
            if not self.privileged_mode:
                raise Exception("Privileged instruction executed in user mode")
        elif opcode == 0x11:  # ENTER_PRIVILEGED
            self.privileged_mode = True
        elif opcode == 0x12:  # EXIT_PRIVILEGED
            self.privileged_mode = False
        else:
            raise ValueError("Invalid opcode")

    def run(self):
        while self.pc < len(self.memory) and self.instruction_count < 100:
            instruction = self.fetch()
            self.execute(instruction)

    def clear_memory(self):
        self.memory = [0] * 1024
        self.memory_protection = [False] * 1024

class CPUSimulatorGUI:
    def __init__(self, cpu):
        self.cpu = cpu
        self.window = tk.Tk()
        self.window.title("CPU Simulator")
        self.create_widgets()

    def create_widgets(self):
        # Instruction Entry
        instruction_frame = ttk.Frame(self.window)
        instruction_frame.pack(pady=10)
        instruction_label = ttk.Label(instruction_frame, text="Instruction:")
        instruction_label.pack(side=tk.LEFT)
        self.instruction_entry = ttk.Entry(instruction_frame, width=30)
        self.instruction_entry.pack(side=tk.LEFT)
        load_button = ttk.Button(instruction_frame, text="Load", command=self.load_instruction)
        load_button.pack(side=tk.LEFT)

        # Program Frame
        program_frame = ttk.Frame(self.window)
        program_frame.pack(pady=10)
        program_label = ttk.Label(program_frame, text="Program:")
        program_label.pack(side=tk.LEFT)
        self.program_text = scrolledtext.ScrolledText(program_frame, width=40, height=10)
        self.program_text.pack(side=tk.LEFT)
        run_button = ttk.Button(program_frame, text="Run", command=self.run_program)
        run_button.pack(side=tk.LEFT)
        clear_button = ttk.Button(program_frame, text="Clear Memory", command=self.clear_memory)
        clear_button.pack(side=tk.LEFT)

        # Registers and Memory Frame
        reg_mem_frame = ttk.Frame(self.window)
        reg_mem_frame.pack(pady=10)
        registers_label = ttk.Label(reg_mem_frame, text="Registers:")
        registers_label.pack(side=tk.LEFT)
        self.registers_text = scrolledtext.ScrolledText(reg_mem_frame, width=20, height=10)
        self.registers_text.pack(side=tk.LEFT)
        memory_label = ttk.Label(reg_mem_frame, text="Memory:")
        memory_label.pack(side=tk.LEFT)
        self.memory_text = scrolledtext.ScrolledText(reg_mem_frame, width=20, height=10)
        self.memory_text.pack(side=tk.LEFT)

        # Exploits Frame
        exploits_frame = ttk.Frame(self.window)
        exploits_frame.pack(pady=10)
        exploits_label = ttk.Label(exploits_frame, text="Exploits:")
        exploits_label.pack()
        self.exploits_text = scrolledtext.ScrolledText(exploits_frame, width=40, height=10)
        self.exploits_text.pack()

    def load_instruction(self):
        instruction = self.instruction_entry.get().strip()
        if instruction:
            self.program_text.insert(tk.END, instruction + "\n")
            self.instruction_entry.delete(0, tk.END)

    def run_program(self):
        self.registers_text.delete(1.0, tk.END)
        self.memory_text.delete(1.0, tk.END)
        self.exploits_text.delete(1.0, tk.END)
        program = self.program_text.get(1.0, tk.END).split("\n")
        program = [line.strip() for line in program if line.strip()]
        instructions = []
        for instruction in program:
            try:
                opcode = int(instruction.replace(" ", ""), 16)
                instructions.append(opcode)
            except ValueError:
                pass
        self.cpu.load_program(instructions)
        self.cpu.run()
        self.update_registers()
        self.update_memory()
        self.check_exploits()

    def update_registers(self):
        for i, value in enumerate(self.cpu.registers):
            self.registers_text.insert(tk.END, f"R{i}: {value}\n")

    def update_memory(self):
        for i, value in enumerate(self.cpu.memory):
            if value != 0:
                self.memory_text.insert(tk.END, f"{i}: {value}\n")

    def check_exploits(self):
        # Buffer Overflow
        if len(self.cpu.memory) > 1024:
            self.exploits_text.insert(tk.END, "Buffer Overflow Exploit Successful!\n")

        # Arbitrary Code Execution
        if self.cpu.memory[1000] == 0xDEADBEEF:
            self.exploits_text.insert(tk.END, "Arbitrary Code Execution Exploit Successful!\n")

        # Uninitialized Memory
        if self.cpu.registers[7] != 0:
            self.exploits_text.insert(tk.END, "Uninitialized Memory Exploit Successful!\n")

        # Lack of Input Validation
        if self.cpu.pc >= len(self.cpu.memory):
            self.exploits_text.insert(tk.END, "Lack of Input Validation Exploit Successful!\n")

        # Division by Zero
        if self.cpu.registers[2] == 0 and self.cpu.registers[1] != 0:
            self.exploits_text.insert(tk.END, "Division by Zero Exploit Successful!\n")

        # Speculative Execution
        if self.cpu.memory[500] == 0xCAFEBABE:
            self.exploits_text.insert(tk.END, "Speculative Execution Exploit Successful!\n")

        # Cache Side-Channel
        if self.cpu.registers[1] == 0x1234:
            self.exploits_text.insert(tk.END, "Cache Side-Channel Exploit Successful!\n")

        # Privilege Escalation
        if not self.cpu.privileged_mode:
            self.exploits_text.insert(tk.END, "Privilege Escalation Exploit Successful!\n")

        # Stack Overflow
        if len(self.cpu.stack) > 100:
            self.exploits_text.insert(tk.END, "Stack Overflow Exploit Successful!\n")

        # Return Address Manipulation
        if self.cpu.pc == 0x1234:
            self.exploits_text.insert(tk.END, "Return Address Manipulation Exploit Successful!\n")

    def clear_memory(self):
        self.cpu.clear_memory()
        self.memory_text.delete(1.0, tk.END)

    def run(self):
        self.window.mainloop()

def main():
    cpu = CPU()
    gui = CPUSimulatorGUI(cpu)
    gui.run()

if __name__ == "__main__":
    main()
