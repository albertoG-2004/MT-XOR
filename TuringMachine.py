class TuringMachine:
    def xor_binary(self, binary_1, binary_key):
        xor_result = ""
        for b1, b2 in zip(binary_1, binary_key):
            if b1 == b2:
                xor_result += "0"
            else:
                xor_result += "1"
        return xor_result

    def decrypt_xor_binary(self, binary_1, binary_key):
        return self.xor_binary(binary_1, binary_key)