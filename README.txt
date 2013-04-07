mzdis.py: A disassembler for MZ executables (i.e. MS-DOS .exe files)
by Ben "GreaseMonkey" Russell, 2013 - Public Domain (or CC0, if you wish)

usage:
	python2 mzdis.py infile.exe outfile.asm

it's that easy. (except for the fact that it currently supports virtually nothing so you have to beat the crap out of it to disassemble stuff, also it does not disassemble switch tables as the segmentation stuff is crap at the moment, i HATE real mode)

