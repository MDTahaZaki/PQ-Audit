# Dummy bqphy module for hackathon simulation
# This file mocks the proprietary BosonQ Psi SDK so that 'import bqphy' succeeds.

__version__ = "1.0.0"

class Model:
    pass

class Solver:
    def __init__(self, model=None):
        self.model = model
        
    def optimize(self):
        return True
