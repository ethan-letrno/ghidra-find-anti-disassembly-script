#Script used to identify anti-disassembly techniques
#@author Cody Ickes, Ethan Letourneau
#@category Code-correction
#@keybinding 
#@menupath 
#@toolbar 

def fix_code(address):
	if proceed:
		proceed_with_overwrite = askYesNo("Overwrite?", "Do you want to overwrite the code at 0x" + str(address))
	if not proceed or proceed_with_overwrite:
		listing.clearCodeUnits(address, address, True)
		disassemble(address)

proceed = askYesNo("Ask to overwrite?", "Do you want to be prompted for every overwrite?")

# Set used to keep track of anti-disassembly technique addresses (prevents redundancy)
techLocs = set()

multiPass = askYesNo("Perform multiple passes?", "Perform multiple passes? (Script runs until no techniques are found)\nWARNING: Infinite loop may occur and require app shutdown (no saving)")

while True:
	techFound = False

	listing = currentProgram.getListing()
	instr_list = listing.getInstructions(1)

	for instr in instr_list:
		mnemonic = instr.getMnemonicString()

		# TODO: Add more constant idenitifiers
		# Looking for potential constant branches
		if mnemonic == "XOR":

			try:
				op1 = instr.getOpObjects(0)
				op2 = instr.getOpObjects(1)

				# Checks if zero flag is set
				if op1[0] == op2[0]:
					next_instr = instr.getNext()
					next_mnemonic = next_instr.getMnemonicString()

					# Checks if jump is being taken based on zero flag
					if str(next_instr.getAddress()) not in techLocs and (next_mnemonic == "JZ" or next_mnemonic == "JE" or next_mnemonic == "JLE" or next_mnemonic == "JGE"):
						addr = next_instr.getAddress()
						j_addr = next_instr.getOpObjects(0)[0]
						print("Constant branch condition at " + str(addr) + ". Jumps to " + str(j_addr))
						# Storing address in set to check if already handled in future checks
						techLocs.add(str(addr))
						techFound = True
						# Showing hidden code
						fix_code(j_addr)

			except Exception as e:
				print(e)
				pass

		# Multiple jumps to the same target
		elif mnemonic == "JZ" or mnemonic == "JNZ" or mnemonic == "JE" or mnemonic == "JNE":
			try:
				next_instr = instr.getNext()
				next_mnemonic = next_instr.getMnemonicString()
				if next_mnemonic == "JZ" or next_mnemonic == "JNZ" or next_mnemonic == "JE" or next_mnemonic == "JNE":
					j_addr1 = instr.getOpObjects(0)[0]
					j_addr2 = next_instr.getOpObjects(0)[0]

					if str(instr.getAddress()) not in techLocs and (j_addr1 == j_addr2 and (((mnemonic == "JZ" or mnemonic == "JE") and (next_mnemonic == "JNZ" or next_mnemonic == "JNE")) or ((mnemonic == "JNZ" or mnemonic == "JNE") and (next_mnemonic == "JZ" or next_mnemonic == "JE")))):
						addr = instr.getAddress()
						print("Multiple jumps to same target at " + str(addr) + ". Jumps to " + str(j_addr1))
						# Storing address in set to check if already handled in future checks
						techLocs.add(str(addr))
						techFound = True
						# Showing hidden code
						fix_code(j_addr1)

			except:
				print("Same target error")
				pass

		# Impossible disassembly
		if str(instr.getAddress()) not in techLocs and mnemonic[0] == "J" and getInstructionAt(instr.getOpObjects(0)[0]) is None:
			try:
				valid_addr = getDataAt(instr.getOpObjects(0)[0]).isPointer()
			except:
				valid_addr = False

			if not valid_addr:
				addr = instr.getAddress()
				j_addr = instr.getOpObjects(0)[0]
				print("Jump to impossible disassembly segment at " + str(addr) + ". Jumps to " + str(j_addr))
				techLocs.add(str(addr))
				techFound = True
				# Show hidden code
				fix_code(j_addr)

	if not multiPass or not techFound:
		break