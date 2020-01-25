from binaryninja import RegisterInfo


def get_regs():
    regs = dict()
    regs['sp'] = RegisterInfo('sp', 4)
    for i in range(4):
        regs['r{}'.format(i)] = RegisterInfo('r{}'.format(i), 4)
    return regs


GPR = {
    0 : 'r0',
    1 : 'r1',
    2 : 'r2',
    3 : 'r3'
}
