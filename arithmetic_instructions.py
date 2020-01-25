from .dumb_instruction import RegReg


class ADD(RegReg):
    opcode = 0x10
    mnemonic = "add"

    def get_instruction_low_level_il(self, data, addr, il):
        reg1 = il.reg(4, self.args[0])
        reg2 = il.reg(4, self.args[1])
        add = il.add(4, reg1, reg2)
        op = il.set_reg(4, self.args[0], add)
        il.append(op)
        return self.length
