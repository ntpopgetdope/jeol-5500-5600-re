import struct
import traceback
import os
import math

from binaryninja import *
from types import *

from .h8300dis import *
from .h8300lift import InstructionIL 


# https://api.binary.ninja/binaryninja.architecture-module.html
# http://www.bitsavers.org/components/hitachi/h8/1990_H04_Hitachi_H8_330_HD6473308_HD643308_Hardware_Manual.pdf
# https://github.com/ntpopgetdope/jeol-5500-5600-re/blob/main/doc/1998_R03_Hitachi_H8_336_337_338_HD6473388_Hardware_Manual.pdf

class H8300(Architecture):
    name = 'H8/300' # H8/338

    address_size     = 2
    default_int_size = 1
    instr_alignment  = 1
    max_instr_length = 10

    endianness = Endianness.BigEndian

    '''
    2.2.1 General Registers

    All the general registers can be used as both data registers and address registers. When used as
    address registers, the general registers are accessed as 16-bit registers (R0 to R7). When used as
    data registers, they can be accessed as 16-bit registers, or the high and low bytes can be accessed
    separately as 8-bit registers (R0H to R7H and R0L to R7L).
    '''
    regs = {
        # -- General Registers --
        'R0': RegisterInfo( 'R0', 2 ),
        'R1': RegisterInfo( 'R1', 2 ),
        'R2': RegisterInfo( 'R2', 2 ),
        'R3': RegisterInfo( 'R3', 2 ),
        'R4': RegisterInfo( 'R4', 2 ),
        'R5': RegisterInfo( 'R5', 2 ),
        'R6': RegisterInfo( 'R6', 2 ),
        'R7': RegisterInfo( 'R7', 2 ),

            # General Registers Lower 8-bits
            'R0L': RegisterInfo( 'R0', 1, 0 ),
            'R1L': RegisterInfo( 'R1', 1, 0 ),
            'R2L': RegisterInfo( 'R2', 1, 0 ),
            'R3L': RegisterInfo( 'R3', 1, 0 ),
            'R4L': RegisterInfo( 'R4', 1, 0 ),
            'R5L': RegisterInfo( 'R5', 1, 0 ),
            'R6L': RegisterInfo( 'R6', 1, 0 ),
            'R7L': RegisterInfo( 'R7', 1, 0 ),
    
            # General Registers Upper 8-bits
            'R0H': RegisterInfo( 'R0', 1, 1 ),
            'R1H': RegisterInfo( 'R1', 1, 1 ),
            'R2H': RegisterInfo( 'R2', 1, 1 ),
            'R3H': RegisterInfo( 'R3', 1, 1 ),
            'R4H': RegisterInfo( 'R4', 1, 1 ),
            'R5H': RegisterInfo( 'R5', 1, 1 ),
            'R6H': RegisterInfo( 'R6', 1, 1 ),
            'R7H': RegisterInfo( 'R7', 1, 1 ),

        # -- Control Registers --
        'PC' : RegisterInfo( 'PC',  2 ), # Program Counter
        'CCR': RegisterInfo( 'CCR', 1 ), # Condition Code Register
    }

    '''
    2.2.1 General Registers

    R7 also functions as the stack pointer, used implicitly
    by hardware in processing interrupts & subroutine calls.
    '''
    stack_pointer = "R7"

    # CCR reg:
    flags = [
        'I',  # Bit 7: Interrupt Mask Bit (I)
        'U',  # Bit 6: User Bit           (U)
        'H',  # Bit 5: Half-Carry Flag    (H)
        'U2', # Bit 4: User Bit           (U)
        'N',  # Bit 3: Negative Flag      (N)
        'Z',  # Bit 2: Zero Flag          (Z)
        'V',  # Bit 1: Overflow Flag      (V)
        'C',  # Bit 0: Carry Flag         (C)
    ]

    flag_roles = {
        # Facilitates overriding handling
        # in `get_flag_write_low_level_il`
        'I' : FlagRole.SpecialFlagRole,
        'U' : FlagRole.SpecialFlagRole,
        'U2': FlagRole.SpecialFlagRole,

        # Flags with binja defined behaviour
        'H' : FlagRole.HalfCarryFlagRole,
        'N' : FlagRole.NegativeSignFlagRole,
        'Z' : FlagRole.ZeroFlagRole,
        'V' : FlagRole.OverflowFlagRole,
        'V' : FlagRole.CarryFlagRole
    }
    
    flag_write_types = [
        'none',
        '*',
        'C',
        'Z',
    ]

    flags_written_by_flag_write_type = {
        'none': [],
        '*'   : ['H', 'N', 'Z', 'V', 'C'],
        'C'   : ['C'],
        'Z'   : ['Z'],
    }
    
    # TODO:
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_UGT: ['C', 'Z'], # hi
        LowLevelILFlagCondition.LLFC_ULE: ['C', 'Z'], # ls
        LowLevelILFlagCondition.LLFC_UGE: ['C'], # cs
        LowLevelILFlagCondition.LLFC_ULT: ['C'], # cs
        LowLevelILFlagCondition.LLFC_NE:  ['Z'], # ne
        LowLevelILFlagCondition.LLFC_E:   ['Z'], # eq
        LowLevelILFlagCondition.LLFC_NO:  ['V'], # vc
        LowLevelILFlagCondition.LLFC_O:   ['V'], # vs
        LowLevelILFlagCondition.LLFC_POS: ['N'], # pl
        LowLevelILFlagCondition.LLFC_NEG: ['N'], # mi
        LowLevelILFlagCondition.LLFC_SGE: ['N', 'V'], # ge
        LowLevelILFlagCondition.LLFC_SLT: ['N', 'V'], # lt
        LowLevelILFlagCondition.LLFC_SGT: ['N', 'V', 'Z'], # gt
        LowLevelILFlagCondition.LLFC_SLE: ['N', 'V', 'Z'], # le
    }
    
    # TODO: huh...
    """
    semantic_flag_classes = ['class_bitstuff']

    semantic_flag_groups = ['group_e', 'group_ne', 'group_lt']
    
    flags_required_for_semantic_flag_group = {
        'group_lt': ['c'],
        'group_e': ['z'],
        'group_ne': ['z']
    }
    
    flag_conditions_for_semantic_flag_group = {
        #'group_e': {None: LowLevelILFlagCondition.LLFC_E},
        #'group_ne': {None: LowLevelILFlagCondition.LLFC_NE}
    }

    # MAP (condition x class) -> flags
    def get_flags_required_for_flag_condition(self, cond, sem_class):
        #LogDebug('incoming cond: %s, incoming sem_class: %s' % (str(cond), str(sem_class)))

        if sem_class == None:
            lookup = {
                # Z, zero flag for == and !=
                LowLevelILFlagCondition.LLFC_E: ['z'],
                LowLevelILFlagCondition.LLFC_NE: ['z'],
                LowLevelILFlagCondition.LLFC_NEG: ['n'],
                LowLevelILFlagCondition.LLFC_UGE: ['c'],
                LowLevelILFlagCondition.LLFC_ULT: ['c']
            }

            if cond in lookup:
                return lookup[cond]

        return []    
    """

    # Helper functions.
    @staticmethod
    def decode_instruction(data, addr):
        if len(data) < 2:
            return None, None, None


        inst, size, match = tryToParse(data) # in h8300dis

        if inst == None:
            return None, None, None

        return inst, size, match

    @staticmethod
    def regFrom(reg, size):
        reg_str = "???"
        if size == 8:
            if((reg&0x8) == 0):
                reg_str = "r"+str(reg&7)+"h"
            else:
                reg_str = "r"+str(reg&7)+"l"
        elif size == 16:
            if((reg&0x8) == 0):
                reg_str = "r"+str(reg&7)
            else:
                reg_str = "e"+str(reg&7)
        elif size == 32:
            reg_str = "er"+str(reg)
        return reg_str

    @staticmethod
    def signOffset(off, size):
        if size == 8:
            off = off & 0xFF
            return off | (-(off & 0x80))
        elif size == 16:
            off = off & 0xFFFF
            return off | (-(off & 0x8000))
        elif size == 24:
            off = off & 0xFFFFFF
            return off | (-(off & 0x800000))
        elif size == 32:
            off = off & 0xFFFFFFFF
            return off | (-(off & 0x80000000))
        return off


    # Binja architecture implementation.
    def get_instruction_info(self, data, addr):
    
        inst, size, match = self.decode_instruction(data, addr)
        
        if inst == None:
            return None
            
        result = InstructionInfo()
        result.length = size
        
        instName = inst[0].split(" ")[0]
        
        JMP_NAMES = ["BHI", "BLS", "BHS", "BLO", "BNE", "BEQ", "BVC", "BPL", "BMI", "BGE", "BLT", "BGT", "BLE" ] # BF never branches
        # "BSR"
        # JMP, JSR

        if not ((instName in JMP_NAMES) or instName == "BT" or instName == "BSR" or instName == "JMP" or instName == "JSR" or instName == "RTS" or instName == "RTE"):
            return result
            
        if instName == "RTE":
            # EXCEPTION RETURN
            result.add_branch(BranchType.FunctionReturn)
        
        if instName == "RTS":
            # RETURN
            result.add_branch(BranchType.FunctionReturn)
            
        if instName == "BT":
            # UNCONDITIONAL JUMP
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    result.add_branch(BranchType.UnconditionalBranch, addr + size + self.signOffset(match[l[2]], l[1]))
        
        
            
        if instName in JMP_NAMES:
            # CONDITIONAL BRANCH
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    result.add_branch(BranchType.TrueBranch, addr + size + self.signOffset(match[l[2]], l[1]))
            result.add_branch(BranchType.FalseBranch, addr + size)


        if instName == "BSR":
            # DIRECT CALL
            for l in inst[2]:
                if l[0] == TYPE_PCOFFSET:
                    result.add_branch(BranchType.CallDestination, addr + size + self.signOffset(match[l[2]], l[1]))
            
        if instName == "JMP":
            if inst[2][0][0] == TYPE_ABS:
                result.add_branch(BranchType.UnconditionalBranch, match[inst[2][0][3]])
            else:
                # UNCONDITIONAL JUMP TO REGISTER OR DOUBLE MEMORY LOOKUP
                result.add_branch(BranchType.IndirectBranch)    
            
        if instName == "JSR":
            if inst[2][0][0] == TYPE_ABS:
                result.add_branch(BranchType.CallDestination, match[inst[2][0][3]])
            else:
                # UNCONDITIONAL CALL TO REGISTER OR DOUBLE MEMORY LOOKUP
                result.add_branch(BranchType.IndirectBranch)    

        """
        if obj.name in ["CALL0", "CALL4", "CALL8", "CALL12"]:
            # DIRECT CALL
            for l in obj.prop["format"]:
                if l[0] == "TYPE_LABEL":
                    result.add_branch(BranchType.CallDestination, l[1])

        if obj.name in ["JX"]:
            # UNCONDITIONAL JUMP TO REGISTER
            result.add_branch(BranchType.IndirectBranch)    
        """
        return result

        
    def get_instruction_text(self, data, addr):
        inst, size, match = self.decode_instruction(data, addr)
        
        if inst == None:
            return None
            
        result = []

        instName = inst[0].split(" ")[0]
        result.append(InstructionTextToken( InstructionTextTokenType.InstructionToken, instName))
        
        """
        TYPE_ATREG = "atreg" # size, access size, offset / '+' / '-' / None, letter
        TYPE_OFFSET = "offset" # size, letter
        TYPE_PCOFFSET = "pcoffset" # size
        """
        
        parIndex = 0
        for l in inst[2]:
            if parIndex > 0:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ','))
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
            
            if l[0] == TYPE_IMM:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, '#'))
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(match[l[2]]), match[l[2]]))
            elif l[0] == TYPE_CONST:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, '#'))
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(l[1]), l[1]))
            elif l[0] == TYPE_REGCCR:
                result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, "ccr"))
            elif l[0] == TYPE_ABS:
                absAddr = match[l[3]]
                result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '@'))
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(absAddr), absAddr))
                result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ''))
            elif l[0] == TYPE_ATABS:
                absAddr = match[l[3]]
                result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '@@'))
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(absAddr), absAddr))
                result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ''))
            elif l[0] == TYPE_ATREG:
                reg = match[l[4]]
                regStr = self.regFrom(reg, l[1])
                
                if l[3] == None or l[3] == '-' or l[3] == '+':

                    result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '@'))
                    if l[3] == '-':
                        result.append(InstructionTextToken(InstructionTextTokenType.TextToken, '-'))
                    result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, regStr))
                    if l[3] == '+':
                        result.append(InstructionTextToken(InstructionTextTokenType.TextToken, '+'))
                    result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ''))
                else:
                    offset = self.signOffset(match[l[3][2]], l[3][1])
                    
                    result.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken, '@('))
                    result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(offset), offset))
                    result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ','))
                    result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, regStr))
                    result.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken, ')'))
   
            elif l[0] == TYPE_REG:
                reg = match[l[2]]
                regStr = self.regFrom(reg, l[1])
                result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, regStr))
            elif l[0] == TYPE_PCOFFSET:
                pcOffset = self.signOffset(match[l[2]], l[1])
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, hex(addr+pcOffset+size), addr+pcOffset+size))
            #    
            parIndex = parIndex + 1
            
        return result, size


    def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
        return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)


    def get_instruction_low_level_il(self, data, addr, il):
        if len(data) < 2: return None
        inst, size, match = self.decode_instruction(data, addr)
        if inst == None: return None

        instName = inst[0].split(" ")[0]
        
        args = []
        
        for l in inst[2]:
            if l[0] == TYPE_IMM:
                args.append((TYPE_IMM, math.ceil(l[1]/8), match[l[2]]))
            elif l[0] == TYPE_CONST:
                args.append((TYPE_CONST, l[1]))
            elif l[0] == TYPE_REGCCR:
                args.append((TYPE_REGCCR))
            elif l[0] == TYPE_ABS:
                args.append((TYPE_ABS, math.ceil(l[1]/8), math.ceil(l[2]/8), match[l[3]]))
            elif l[0] == TYPE_ATABS:
                args.append((TYPE_ATABS, math.ceil(l[1]/8), math.ceil(l[2]/8), match[l[3]]))
            elif l[0] == TYPE_ATREG:
                r = self.regFrom(match[l[4]], l[1])
                sizeO = math.ceil(l[1]/8)
                sizeA = math.ceil(l[2]/8)
                if l[3] == None or l[3] == '-' or l[3] == '+':
                    if l[3] == '-':
                        args.append((TYPE_ATREG, sizeO, sizeA, "-", r))
                    elif l[3] == '+':
                        args.append((TYPE_ATREG, sizeO, sizeA, "+", r))
                    else:
                        args.append((TYPE_ATREG, sizeO, sizeA, "@", r))
                else:
                    args.append((TYPE_ATREG, sizeO, sizeA, "offset", r, self.signOffset(match[l[3][2]], l[3][1])))
            elif l[0] == TYPE_REG:
                args.append((TYPE_REG, math.ceil(l[1]/8), self.regFrom(match[l[2]], l[1])))
            elif l[0] == TYPE_PCOFFSET:
                args.append((TYPE_PCOFFSET, math.ceil(l[1]/8), addr+self.signOffset(match[l[2]], l[1])+size, addr+size))
        
        if InstructionIL.get(instName) is not None:
            instLifted = InstructionIL[instName](il, args)
            if isinstance(instLifted, list):
                for i in instLifted:
                    if isinstance(i, LambdaType):
                        i(il, args)
                    else:    
                        il.append(i)
            elif instLifted is not None:
                il.append(instLifted)
        else:
            il.append(il.unimplemented())
        

        return size
        
H8300.register()
