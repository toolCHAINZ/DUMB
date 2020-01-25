from binaryninja import Architecture, Platform

from .dumb_arch import DUMBArchitecture
from .dumb_view import DumbView

# In order for binary ninja to use our architecture, we must register it.
DUMBArchitecture.register()

# The following section implements a "platform" for the architecture.
# Platform here means something like Windows or Linux. The following code
# makes one that doesn't do anything special.

dumb_arch = Architecture['DUMB']
standalone = dumb_arch.standalone_platform


class DUMBPlatform(Platform):
    name = 'DUMB'


dumb_platform = DUMBPlatform(dumb_arch)
dumb_platform.register('DUMB')

# Binary Views must be registered to Binary Ninja in order to be used
DumbView.register()
