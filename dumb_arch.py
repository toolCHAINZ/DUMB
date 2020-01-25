from typing import List

from binaryninja import log_error

from .control_instructions import *  # Module implementing control instructions
from .logic_instructions import *  # Module implementing logic instructions
from .arithmetic_instructions import *  # Module implementing arithmetic instructions
from .data_movement_instructions import *  # Module implementing data movement instructions

from .dumb_instruction import DUMBInstruction
from .dumb_register import get_regs


class DUMBArchitecture(Architecture):
    """
    This class is the main class for our custom architecture. It implements
    get_instruction_text, get_instruction_info, and get_instruction_low_level_il,
    which every architecture must.
    """
    instructions: List[DUMBInstruction] = [JLT, RET, CALL, ADD, AND, XOR, OR, MOV, MOVI]
    name = 'DUMB'
    stack_pointer = 'sp'
    regs = get_regs()

    def decode_instruction(self, data: bytes, addr: int):
        """
        Iterates through all the decoders that we have defined and attempts
        to decode the current data.

        If nothing returns, we have not implemented
        the instruction. If 2 or more return, then we have done something wrong,
        resulting in ambiguous behavior. If only one returns, we are good to go!
        """
        decode_results = []
        for a in self.instructions:
            decode_result = a.decode(data, addr)
            if decode_result is None:
                continue
            decode_results.append(decode_result)
        if len(decode_results) > 1:
            log_error(f"Ambiguous decoding: {decode_result}")
            return None
        elif len(decode_results) == 0:
            log_error(f"No implementation found for instruction at {hex(addr)}")
            return None
        return decode_results[0]

    def get_instruction_text(self, data, addr):
        """Pull tokenization from implementing class"""
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            return [[], 1]
        return decode_result.get_instruction_text(data, addr)

    def get_instruction_info(self, data, addr):
        """Pull instruction info from implementing class"""
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            i = InstructionInfo()
            i.length = 1
            return i
        return decode_result.get_instruction_info(data, addr)

    def get_instruction_low_level_il(self, data, addr, il):
        """Pull LLIL from implementing class"""
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            return 1
        else:
            return decode_result.get_instruction_low_level_il(data, addr, il)
