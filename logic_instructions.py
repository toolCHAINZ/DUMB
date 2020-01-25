from .dumb_instruction import RegReg


class AND(RegReg):
    opcode = 0x20
    mnemonic = "and"

    def get_instruction_low_level_il(self, data, addr, il):
        reg1 = il.reg(4, self.args[0])
        reg2 = il.reg(4, self.args[1])
        add = il.and_expr(4, reg1, reg2)
        op = il.set_reg(4, self.args[0], add)
        il.append(op)
        return self.length


class XOR(RegReg):
    opcode = 0x40
    mnemonic = "xor"

    def get_instruction_low_level_il(self, data, addr, il):
        reg1 = il.reg(4, self.args[0])
        reg2 = il.reg(4, self.args[1])
        add = il.xor_expr(4, reg1, reg2)
        op = il.set_reg(4, self.args[0], add)
        il.append(op)
        return self.length


class OR(RegReg):
    opcode = 0x30
    mnemonic = "or"

    def get_instruction_low_level_il(self, data, addr, il):
        reg1 = il.reg(4, self.args[0])
        reg2 = il.reg(4, self.args[1])
        add = il.or_expr(4, reg1, reg2)
        op = il.set_reg(4, self.args[0], add)
        il.append(op)
        return self.length
