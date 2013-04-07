import sys, struct

class MZHeader:
	def __init__(self, fp):
		magic = fp.read(2)
		if magic != "MZ":
			raise Exception("not a MZ EXE")
			# really why the hell would you use ZM to mark stuff that's just wrong
		len_rem, len_quo, len_reloc = struct.unpack("<HHH", fp.read(6))
		hdr_size, alloc_min, alloc_max, init_ss = struct.unpack("<HHHH", fp.read(8))
		init_sp, checksum, init_ip, init_cs = struct.unpack("<HHHH", fp.read(8))
		reloc_offs, overlay = struct.unpack("<HH", fp.read(4))
		#print len_rem, len_quo, len_reloc, hdr_size, alloc_min, alloc_max, init_ss, init_sp, checksum, init_ip, init_cs, reloc_offs, overlay

		self.length = len_rem + (len_quo-1)*512
		self.hdr_size = hdr_size*16

		fp.seek(reloc_offs)
		self.relocs = [struct.unpack("<HH", fp.read(4)) for i in xrange(len_reloc)]

		self.init_cs, self.init_ip = init_cs, init_ip
		self.init_ss, self.init_sp = init_ss, init_sp

IMEMMAP = [[3,6],[3,7],[5,6],[5,7],[6],[7],[5],[3]]
ISEGMAP = {"DS:" : "DS", "ES:" : "ES", "CS:" : "CS", "SS:" : "SS", "" : "DS"}
REGSEG = ["ES", "CS", "SS", "DS"]
REG16 = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"]
REG8 = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"]
REG16M = ["BX+SI", "BX+DI", "BP+SI", "BP+DI", "SI", "DI", "BP", "BX"]
ALUOP = ["ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP"]
CJMPOP = ["JO", "JNO", "JB", "JNB", "JZ", "JNZ", "JBE", "JA", "JS", "JNS", "JPE", "JPO", "JL", "JGE", "JLE", "JG"]
LOOPOP = ["LOOPNZ", "LOOPZ", "LOOP", "JCXZ"]
SHOP = ["ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "???SAL", "SAR"]
REGMAP8 = [0,2,4,6,1,3,5,7]
TYPLENS = {
	"afar": 2,
	"r8": 1, "r16": 1, "rseg": 1,
	"8rm": 2, "8rm8": 3, "8rm16": 3,
	"16rm": 2, "16rm8": 3, "16rm16": 3,
	"8m16": 2, "16m16": 2,
	"imm8": 1, "imm16": 1,
	"j8": 1, "j16": 1,
	"c1": 0, "c3": 0,
}

(DBLANK,
DOPSTART, DOPMID,
DIU8, DIS8, DIU16, DIS16,
) = xrange(7)

class MZ:
	def __init__(self, fp):
		self.hdr = MZHeader(fp)
		fp.seek(0)
		self.data = [ord(v) for v in fp.read(self.hdr.length)]
		# TODO? apply reloc table?

	def fetch8(self, cs, ip):
		pt = cs*16+ip+self.hdr.hdr_size 
		pt &= 0xFFFFF
		bt = (0 if pt < 0 or pt >= len(self.data) else self.data[pt])
		return bt, cs, (ip+1)&0xFFFF 
	
	def fetch16(self, cs, ip):
		b1, cs, ip = self.fetch8(cs, ip)
		b2, cs, ip = self.fetch8(cs, ip)
		return (b2<<8)+b1, cs, ip
	
	def fetch8s(self, cs, ip):
		bt, cs, ip = self.fetch8(cs, ip)
		return ((bt+0x80)&255)-0x80, cs, ip
	
	def fetch16s(self, cs, ip):
		bt, cs, ip = self.fetch16(cs, ip)
		return ((bt+0x8000)&0xFFFF)-0x8000, cs, ip
	
	def fetchmodrm(self, cs, ip, rtype, es):
		modrm, cs, ip = self.fetch8(cs, ip)
		mod = modrm>>6
		r = (modrm>>3)&7
		m = modrm&7
		
		if mod == 0:
			if m == 6: # FFFFFFFFFFFFFFFFFFFFFFFFUUUU
				imm, cs, ip = self.fetch16(cs, ip)
				return r, [rtype[1:]+"m16", es, imm], cs, ip
			return r, [rtype[1:]+"rm", es, m], cs, ip
		if mod == 1:
			imm, cs, ip = self.fetch8s(cs, ip)
			return r, [rtype[1:]+"rm8", es, m, imm], cs, ip
		if mod == 2:
			imm, cs, ip = self.fetch16(cs, ip)
			return r, [rtype[1:]+"rm16", es, m, imm], cs, ip
		if mod == 3:
			return r, [rtype, m], cs, ip
	
	def lbl16(self, cs, ip):
		#
		pt = (cs*16 + ip + self.hdr.hdr_size) & 0xFFFFF
		if pt in self.dalabel_a2l:
			lbl, lcs, lip = self.dalabel_a2l[pt]
			if lcs == cs:
				return "?_%05i" % lbl

		return "0x%04X" % ip
	
	def lbl16seg(self, regs, seg, ip):
		si = ISEGMAP[seg]
		if si in regs:
			sv = regs[si]
			return self.lbl16(sv, ip)
		
		return "0x%04X" % ip
	
	def opstr(self, l, cs, ip, nip, regs):
		pl = []
		i = 1
		while i < len(l):
			t = l[i]
			i += 1
			if t == "afar":
				pl.append("0x%04X:%s" % (l[i], self.lbl16(l[i], l[i+1])))
				i += 1
			elif t == "r8":
				pl.append(REG8[l[i]])
			elif t == "r16":
				pl.append(REG16[l[i]])
			elif t == "rseg":
				pl.append(REGSEG[l[i]])
			elif t == "8rm":
				pl.append("BYTE [%s%s]" % (l[i], REG16M[l[i+1]]))
				i += 1
			elif t == "8rm8":
				pl.append("BYTE [%s%s%s0x%02X]" % (l[i], REG16M[l[i+1]], "-" if l[i+2] < 0 else "+", abs(l[i+2])))
				i += 2
			elif t == "8rm16":
				pl.append("BYTE [%s%s+%s]" % (l[i], REG16M[l[i+1]], self.lbl16seg(regs, l[i], l[i+2])))
				i += 2
			elif t == "8m16":
				pl.append("BYTE [%s%s]" % (l[i], self.lbl16seg(regs, l[i], l[i+1])))
				i += 1
			elif t == "16rm":
				pl.append("WORD [%s%s]" % (l[i], REG16M[l[i+1]]))
				i += 1
			elif t == "16rm8":
				pl.append("WORD [%s%s%s0x%02X]" % (l[i], REG16M[l[i+1]], "-" if l[i+2] < 0 else "+", abs(l[i+2])))
				i += 2
			elif t == "16rm16":
				pl.append("WORD [%s%s+%s]" % (l[i], REG16M[l[i+1]], self.lbl16seg(regs, l[i], l[i+2])))
				i += 2
			elif t == "16m16":
				pl.append("WORD [%s%s]" % (l[i], self.lbl16seg(regs, l[i], l[i+1])))
				i += 1
			elif t == "imm8":
				pl.append("0x%02X" % l[i])
			elif t == "imm16":
				pl.append("0x%04X" % l[i])
			elif t == "j8":
				pl.append("SHORT %s" % self.lbl16(cs, (l[i]+nip)&0xFFFF))
			elif t == "j16":
				pl.append("NEAR %s" % self.lbl16(cs, (l[i]+nip)&0xFFFF))
			elif t == "c1":
				pl.append("0x01")
				i -= 1
			elif t == "c3":
				pl.append("0x03")
				i -= 1
			else:
				raise Exception("EDOOFUS: unhandled disassembly type %s" % t)
			i += 1

		s = "%-9s %-30s" % (l[0], "" if len(pl) == 0 else ", ".join(pl))
		return s
	
	def addlabel(self, pt, cs, ip):
		if pt in self.dalabel_a2l:
			return
		self.dalabel_offs += 1
		self.dalabel_a2l[pt] = (self.dalabel_offs, cs, ip)
		self.dalabel_l2a[self.dalabel_offs] = (pt, cs, ip)
		#print "?_%05i: %04X:%04X" % (self.dalabel_offs, cs, ip)
	
	def labelmem(self, pt, cs, ip, l, nip, pref, regs, i):
		seg = ISEGMAP[l[i+1]]
		offs = None 
		rset = []
		if l[i] in ["8m16", "16m16"]:
			offs = l[i+2]
		elif l[i] in ["8rm8", "16rm8", "8rm16", "16rm16"]:
			offs = l[i+3]

		if l[i] in ["8rm", "16rm", "8rm8", "16rm8", "8rm16", "16rm16"]:
			rset = IMEMMAP[l[i+2]]

		if offs != None and l[i] not in ["8rm8", "16rm8"]:
			if seg in regs:
				sv = regs[seg]
				ptx = sv*16+offs+self.hdr.hdr_size
				ptx &= 0xFFFFF
				if ptx >= 0 and ptx <= len(self.data):
					self.addlabel(ptx, sv, offs)
				#print sv,offs
		#for r in rset:
		#	if regs[i] != 
	
	def addop(self, pt, cs, ip, l, nip, pref, bregs):
		regs = bregs
		if l[0] in ["SUB", "XOR"] and l[1] in ["r8", "r16"] and l[3] == l[1]:
			if l[1] == "r8":
				regs[REGMAP8[l[2]]] = 0
			elif l[1] == "r16":
				regs[l[2]*2] = 0
				regs[l[2]*2+1] = 0

		if l[0] in ["MOV"] + ALUOP:
			i = 1
			j = TYPLENS[l[i]] + 1 + i

			doop_a = False
			doop_b = False

			# param B
			if l[j] == "r8":
				doop_b = REGMAP8[l[j+1]] in regs
			elif l[j] == "r16":
				doop_b = l[j+1]*2 in regs and l[j+1]*2+1 in regs
			elif l[j] == "rseg":
				doop_b = REGSEG[l[j+1]] in regs
			elif l[j] in ["8rm", "16rm", "8rm8", "16rm8", "8rm16", "16rm16", "8m16", "16m16"]:
				self.labelmem(pt, cs, ip, l, nip, pref, regs, j)
			elif l[j] in ["imm8", "imm16", "c1", "c3"]:
				doop_b = True

			# param A
			if l[0] == "MOV":
				doop_a = l[i] in ("r8", "r16", "rseg")
			elif l[i] == "r8":
				doop_a = REGMAP8[l[i+1]] in regs
			elif l[i] == "r16":
				doop_a = l[i+1]*2 in regs and l[i+1]*2+1 in regs
			elif l[i] == "rseg":
				doop_a = REGSEG[l[i+1]] in regs
			elif l[i] in ["8rm", "16rm", "8rm8", "16rm8", "8rm16", "16rm16", "8m16", "16m16"]:
				self.labelmem(pt, cs, ip, l, nip, pref, regs, i)

			if doop_a and doop_b:
				# get B
				vl = None
				vh = None
				if l[j] == "r8":
					vl = regs[REGMAP8[l[j+1]]]&255
				elif l[j] == "r16":
					vl = regs[l[j+1]*2]&255
					vh = regs[l[j+1]*2+1]&255
				elif l[j] == "rseg":
					vl = regs[REGSEG[l[j+1]]]
					vh = (vl>>8)&255
					vl &= 255
				elif l[j] == "imm8":
					vl = l[j+1]&255
				elif l[j] == "imm16":
					vl = l[j+1]&255
					vh = (l[j+1]>>8)&255
				else:
					raise Exception("invalid arg A")

				# store in A
				if l[0] != "MOV":
					doop_a = False
				if doop_a:
					if l[i] == "r8":
						regs[REGMAP8[l[i+1]]] = vl
					elif l[i] == "r16":
						regs[l[i+1]*2] = vl
						regs[l[i+1]*2+1] = vh
					elif l[i] == "rseg":
						regs[REGSEG[l[i+1]]] = vl|(vh<<8)
					else:
						raise Exception("invalid arg B")
					#print "opa, opb", l

		regs = bregs.copy()
		l[0] = pref + l[0]
		self.daops[pt] = (l, regs)
		
		fip = ip
		while fip != nip:
			if ((cs*16+fip+self.hdr.hdr_size)&0xFFFFF) in self.damap:
				return
			fip = (fip+1)&0xFFFF

		fip = ip
		while fip != nip:
			self.damap[(cs*16+fip+self.hdr.hdr_size)&0xFFFFF] = (DOPSTART if fip == ip else DOPMID, cs)
			fip = (fip+1)&0xFFFF
	
	def disasm_op(self, cs, ip, regs):
		es = ""
		pref = ""

		bpt = cs*16+ip+self.hdr.hdr_size 
		bpt &= 0xFFFFF
		bcs, bip = cs, ip
		#print "%04X:%04X" % (cs, ip),

		while True:
			op, cs, ip = self.fetch8(cs, ip)

			regs["CS"] = cs

			#print "%02X" % op,
			if op < 0x40 and (op&7) < 6:
				otype = ALUOP[(op>>3)&7]
				pb = []
				if (op&7) < 4:
					ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
					py = ["r8" if (op&1) == 0 else "r16", ri]
					pb = px+py if (op&2) == 0 else py+px
				else:
					val, cs, ip = (self.fetch8 if (op&1) == 0 else self.fetch16)(cs, ip)
					pb = ["r8" if (op&1) == 0 else "r16", 0, "imm8" if (op&1) == 0 else "imm16", val]
				self.addop(bpt, bcs, bip, [otype] + pb, ip, pref, regs)
			elif op < 0x20 and (op&7) >= 6:
				ri = op>>3
				r = REGSEG[ri]
				otype = "PUSH" if (op&7) == 6 else "POP"
				self.addop(bpt, bcs, bip, [otype, "rseg", ri], ip, pref, regs)
			elif op >= 0x20 and op < 0x40 and (op&7) == 6:
				es = REGSEG[(op>>3)&3]+":"
				continue
			elif op >= 0x40 and op <= 0x4F:
				ri = op&7
				r = REG16[ri]
				otype = "INC" if op < 0x48 else "DEC"
				self.addop(bpt, bcs, bip, [otype, "r16", ri], ip, pref, regs)
			elif op >= 0x50 and op <= 0x5F:
				otype = "PUSH" if op < 0x58 else "POP"
				self.addop(bpt, bcs, bip, [otype, "r16", (op&7)], ip, pref, regs)
			elif op >= 0x68 and op <= 0x6B: # 80186
				otype = "PUSH" if (op&1) == 0 else "IMUL"
				if (op&1):
					raise Exception("IMUL immediate not supported yet")
				imm, cs, ip = (self.fetch16 if op <= 0x69 else self.fetch8)(cs, ip)
				self.addop(bpt, bcs, bip, [otype] + ["imm16" if op <= 0x69 else "imm8", imm], ip, pref, regs)
			elif op >= 0x70 and op <= 0x7F:
				relp, cs, ip = self.fetch8s(cs, ip)
				self.addop(bpt, bcs, bip, [CJMPOP[op&15], "j8", relp], ip, pref, regs)
				optr = ((ip+relp)&0xFFFF)
				regs = self.disasm_code(cs, optr, regs)
			elif op >= 0x80 and op <= 0x83:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				imm, cs, ip = (self.fetch8s if op == 0x83 else self.fetch16 if op == 0x81 else self.fetch8)(cs, ip)
				self.addop(bpt, bcs, bip, [ALUOP[ri]] + px + ["imm16" if op == 0x82 else "imm8", imm], ip, pref, regs)
			elif op >= 0x84 and op <= 0x87:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				self.addop(bpt, bcs, bip, ["TEST" if op < 0x85 else "XCHG", "r8" if (op&1) == 0 else "r16", ri] + px, ip, pref, regs)
			elif op >= 0x88 and op <= 0x8B:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				py = ["r8" if (op&1) == 0 else "r16", ri]
				pb = px+py if (op&2) == 0 else py+px
				self.addop(bpt, bcs, bip, ["MOV"] + pb, ip, pref, regs)
			elif (op&~2) == 0x8C:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r16", es)
				py = ["rseg", ri&3]
				pb = px+py if (op&2) == 0 else py+px
				self.addop(bpt, bcs, bip, ["MOV"] + pb, ip, pref, regs)
			elif op == 0x8D:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r16", es)
				self.addop(bpt, bcs, bip, ["LEA", "r16", ri] + px, ip, pref, regs)
			elif op >= 0x90 and op <= 0x97:
				self.addop(bpt, bcs, bip, ["XCHG", "r16", op&7, "r16", 0], ip, pref, regs)
			elif (op & 0xFE) == 0x98:
				self.addop(bpt, bcs, bip, [["CBW","CWD"][op&1]], ip, pref, regs)
			elif op == 0x9A:
				optr, cs, ip = self.fetch16(cs, ip)
				oseg, cs, ip = self.fetch16(cs, ip)
				self.addop(bpt, bcs, bip, ["CALL", "afar", oseg, optr], ip, pref, regs)
				regs = self.disasm_code(oseg, optr, regs)
			elif op >= 0x9C and op <= 0x9F:
				self.addop(bpt, bcs, bip, [["PUSHF","POPF","SAHF","LAHF"][op&3]], ip, pref, regs)
			elif op >= 0xA0 and op <= 0xA3:
				val, cs, ip = self.fetch16(cs, ip)
				px = ["8m16" if (op&1) == 0 else "16m16", es, val]
				py = ["r8" if (op&1) == 0 else "r16", 0]
				pb = py+px if (op&2) == 0 else px+py
				self.addop(bpt, bcs, bip, ["MOV"] + pb, ip, pref, regs)
			elif op >= 0xA4 and op <= 0xA7:
				self.addop(bpt, bcs, bip, [["MOV", "CMP"][(op-0xA4)>>1] + "S" + ("B" if (op&1) == 0 else "W")], ip, pref, regs)
			elif op >= 0xA8 and op <= 0xA9:
				val, cs, ip = (self.fetch8 if (op&1) == 0 else self.fetch16)(cs, ip)
				self.addop(bpt, bcs, bip, ["TEST", "r8" if (op&1)==0 else "r16", 0, "imm8" if (op&1)==0 else "imm16", val], ip, pref, regs)
			elif op >= 0xAA and op <= 0xAF:
				self.addop(bpt, bcs, bip, [["STO", "LOD", "SCA"][(op-0xAA)>>1] + "S" + ("B" if (op&1) == 0 else "W")], ip, pref, regs)
			elif op >= 0xB0 and op <= 0xBF:
				val, cs, ip = (self.fetch8 if op < 0xB8 else self.fetch16)(cs, ip)
				ri = op&7
				r = REG8[ri] if op < 0xB8 else REG16[ri]
				self.addop(bpt, bcs, bip, ["MOV", "r8" if op < 0xB8 else "r16", ri, "imm8" if op < 0xB8 else "imm16", val], ip, pref, regs)
			elif op >= 0xC0 and op <= 0xC1: # 80186
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				val, cs, ip = self.fetch8(cs, ip)
				self.addop(bpt, bcs, bip, [SHOP[ri]] + px + ["imm8", val], ip, pref, regs)
			elif op == 0xC2:
				val, cs, ip = self.fetch16(cs, ip)
				self.addop(bpt, bcs, bip, ["RET", "imm16", val], ip, pref, regs)
				return cs, ip, False, regs
			elif op == 0xC3:
				self.addop(bpt, bcs, bip, ["RET"], ip, pref, regs)
				return cs, ip, False, regs
			elif op >= 0xC4 and op <= 0xC5:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r16", es)
				self.addop(bpt, bcs, bip, [["LES", "LDS"][op&1], "r16", ri] + px, ip, pref, regs)
			elif op >= 0xC6 and op <= 0xC7:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				val, cs, ip = (self.fetch8 if (op&1) == 0  else self.fetch16)(cs, ip)
				self.addop(bpt, bcs, bip, ["MOV"] + px + ["imm8" if (op&1) == 0 else "imm16", val], ip, pref, regs)
			elif op == 0xC8: # 80186
				v16, cs, ip = self.fetch16(cs, ip)
				v8, cs, ip = self.fetch8(cs, ip)
				self.addop(bpt, bcs, bip, ["ENTER", "imm16", v16, "imm8", v8], ip, pref, regs)
			elif op == 0xC9: # 80186
				self.addop(bpt, bcs, bip, ["LEAVE"], ip, pref, regs)
			elif op == 0xCA:
				val, cs, ip = self.fetch16(cs, ip)
				self.addop(bpt, bcs, bip, ["RETF", "imm16", val], ip, pref, regs)
				return cs, ip, False, regs
			elif op == 0xCB:
				self.addop(bpt, bcs, bip, ["RETF"], ip, pref, regs)
				return cs, ip, False, regs
			elif op == 0xCD:
				val, cs, ip = self.fetch8(cs, ip)
				self.addop(bpt, bcs, bip, ["INT", "imm8", val], ip, pref, regs)
			elif op >= 0xD0 and op <= 0xD3:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				self.addop(bpt, bcs, bip, [SHOP[ri]] + px + (["c1"] if (op&2)==0 else ["r8", 1]), ip, pref, regs)
			elif op == 0xD7:
				if es != "":
					raise Exception("TODO: non-DS: XLAT")
				self.addop(bpt, bcs, bip, ["XLAT"], ip, pref, regs)
			elif op >= 0xD8 and op <= 0xDF:
				op2, cs, ip = self.fetch8(cs, ip)
				print "FPUOP %02X -- TODO!" % op2
				return cs, ip, False, regs
				raise Exception("TODO: FPU ops")
			elif op >= 0xE0 and op <= 0xE3:
				relp, cs, ip = self.fetch8s(cs, ip)
				self.addop(bpt, bcs, bip, [LOOPOP[op&3], "j8", relp], ip, pref, regs)
				optr = ((ip+relp)&0xFFFF)
				regs = self.disasm_code(cs, optr, regs)
			elif op >= 0xE4 and op <= 0xE7:
				rlen = "r8" if (op&1)==0 else "r16"
				val, cs, ip = self.fetch8(cs, ip)
				px = [rlen, 0]
				py = ["imm8", val]
				pb = ["IN"]+px+py if (op&2)==0 else ["OUT"]+py+px
				self.addop(bpt, bcs, bip, pb, ip, pref, regs)
			elif op >= 0xE8 and op <= 0xEB:
				val, cs, ip = (self.fetch8s if op == 0xEB else self.fetch16)(cs, ip)
				self.addop(bpt, bcs, bip, ["CALL" if op == 0xE8 else "JMP", "j8" if op == 0xEB else "afar" if op == 0xEA else "j16", val], ip, pref, regs)
				optr = ((ip+val if op != 0xEA else val)&0xFFFF)
				regs = self.disasm_code(cs, optr, regs)
				if op != 0xE8:
					return cs, ip, False, regs
			elif op >= 0xEC and op <= 0xEF:
				rlen = "r8" if (op&1)==0 else "r16"
				px = [rlen, 0]
				py = ["r16", 2]
				pb = ["IN"]+px+py if (op&2)==0 else ["OUT"]+py+px
				self.addop(bpt, bcs, bip, pb, ip, pref, regs)
			elif (op&~1) == 0xF2:
				pref += ["REPNZ","REPZ"][op&1]+" "
				continue
			elif op == 0xF5:
				self.addop(bpt, bcs, bip, ["CMC"], ip, pref, regs)
			elif (op & 0xFE) == 0xF6:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				opname = ["TEST","???","NOT","NEG","MUL","IMUL","DIV","IDIV"][ri]
				p = [opname] + px
				if ri == 0:
					val, cs, ip = (self.fetch8 if (op&1) == 0 else self.fetch16)(cs, ip)
					p += ["imm8" if (op&1) == 0 else "imm16", val]
				self.addop(bpt, bcs, bip, p, ip, pref, regs)
			elif op >= 0xF8 and op <= 0xFD:
				self.addop(bpt, bcs, bip, [["CLC", "STC", "CLI", "STI", "CLD", "STD"][op-0xF8]], ip, pref, regs)
			elif (op & 0xFE) == 0xFE:
				ri, px, cs, ip = self.fetchmodrm(cs, ip, "r8" if (op&1) == 0 else "r16", es)
				opname = ["PUSH", "POP", "CALL", "CALLF", "JMP", "JMPF", "PUSH", "???"]
				self.addop(bpt, bcs, bip, [opname[ri]] + px, ip, pref, regs)
				if ri == 4 or ri == 5:
					return cs, ip, False, regs
			else:
				raise Exception("unhandled opcode %02X" % op)
			break

		pt = cs*16+ip+self.hdr.hdr_size 
		pt &= 0xFFFFF
		bpt &= 0xFFFFF

		return cs, ip, True, regs
	
	def disasm_code(self, cs, ip, regs):
		self.addlabel((cs*16+ip+self.hdr.hdr_size)&0xFFFFF, cs, ip)
		while ((cs*16+ip+self.hdr.hdr_size)&0xFFFFF) < len(self.data) and ((cs*16+ip+self.hdr.hdr_size)&0xFFFFF) not in self.daops:
			cs, ip, cont, regs = self.disasm_op(cs, ip, regs)
			if not cont:
				break

		return regs
	
	def disasm(self, fp):
		fp.write("\tBITS 16\n\n")
		fp.write("\t; ENTRY POINT = %04X:%04X\n" % (self.hdr.init_cs, self.hdr.init_ip))
		fp.write("\t; STACK = %04X:%04X\n" % (self.hdr.init_ss, self.hdr.init_sp))
		self.damap = {}
		self.daops = {}
		self.dalabel_a2l = {}
		self.dalabel_l2a = {}
		self.dalabel_offs = 0
		self.disasm_code(self.hdr.init_cs, self.hdr.init_ip, {"CS": self.hdr.init_cs, "SS": self.hdr.init_ss})

		bpt = self.hdr.hdr_size
		seg = 0x0000
		dbacclist = []
		while bpt < len(self.data):
			t, ts = self.damap[bpt] if bpt in self.damap else (DBLANK, seg)

			if (t != DBLANK or len(dbacclist) >= 16 or ts != seg or bpt in self.dalabel_a2l) and len(dbacclist) > 0:
				ip = bpt-seg*16-self.hdr.hdr_size-len(dbacclist)
				ip &= 0xFFFF
				fp.write("\tDB " + ", ".join("0x%02X" % v for v in dbacclist) + " ; %04X:%04X    " % (seg, ip)
					+ "".join("." if v < 0x20 or v >= 0x7F else chr(v) for v in dbacclist) + "\n")
				dbacclist = []

			if ts != seg:
				seg = ts
				fp.write("\tSEGMENT 0x%04X\n" % seg)

			lbl, lcs, lip = (None, None, None) if bpt not in self.dalabel_a2l else self.dalabel_a2l[bpt]
			if lbl:
				fp.write("?_%05i:\n" % lbl)

			if t == DOPSTART:
				pt = bpt
				ip = bpt-seg*16-self.hdr.hdr_size 
				nip = ip
				t = DOPMID
				while t == DOPMID:
					bpt += 1
					nip = (nip+1)&0xFFFF
					t, ts = self.damap[bpt] if bpt in self.damap else (DBLANK, seg)
				ov = self.daops[pt]
				fp.write("\t" + self.opstr(ov[0], seg, ip, nip, ov[1]) + "; %04X:%04X" % (seg, ip) + "\n")
			else:
				dbacclist.append(self.data[bpt])
				bpt += 1

		if len(dbacclist) > 0:
			ip = bpt-seg*16-self.hdr.hdr_size-len(dbacclist)
			ip &= 0xFFFF
			fp.write("\tDB " + ", ".join("0x%02X" % v for v in dbacclist) + " ; %04X:%04X    " % (seg, ip)
				+ "".join("." if v < 0x20 or v >= 0x7F else chr(v) for v in dbacclist) + "\n")


fp = open(sys.argv[1], "rb")
mz = MZ(fp)
fp.close()

fp = open(sys.argv[2], "w")
mz.disasm(fp)
fp.close()

