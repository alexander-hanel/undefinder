'''
Name:
        undefinder.py

Version:
        0.1
        
Description:
		IDAPython script that searches for data between known functions

Author:
        alexander<dot>hanel<at>gmail<dot>com

License:
undefinder.py is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see
<http://www.gnu.org/licenses/>.

'''

class undefinder:
    def __init__(self):
        # self.firstList contains a dictionary of
        # { "id":function_name, "start":function_start_addr, "end":function_end_addr 
        self.firstList = []  
        self.modList = []
        self.populate_mods()
 
    def getKnownFunctions(self):
        "self.firstList is populated with each item in a list with a dictionary of { 'id':function_name, 'start':function_start_addr, 'end':function_end_addr" 
        for funcea in Functions( SegStart( here() ), SegEnd( here() ) ):
            self.firstList.append({"id":GetFunctionName(funcea), "start":GetFunctionAttr(funcea, FUNCATTR_START), "end":GetFunctionAttr(funcea, FUNCATTR_END)})
        return
    
    def calc_dist(self,addr):
        "calcuates the distane of the next aligned address" 
        dist = int(addr % 16)
        if dist < 4:
            return 4 - dist
        if dist < 8:
            return 8 - dist
        if dist < 12:
            return 12 - dist
        if dist < 16:
            return 16 - dist
        else:
            return None

    def check_down(self, func_addr):
        "checks if the data below is a function or other type of data"
        cur_func = idaapi.get_func(func_addr)
        cur_end = cur_func.endEA
        next_func = idaapi.get_next_func(func_addr)
        next_start = None
        # if next_func == None the last function has been found
        # the try/except is used because IDAPython was crashing on
        # the next_func == None comparison if the value was not None
        try:
            if next_func == None:
                next_start = NextAddr(cur_end)
        except:
            next_start = next_func.startEA
        # get start of the next function
        if cur_end == next_start:
            return None, None
        # check if the block is already part of a function
        if GetFunctionName(cur_end) != "":
            return None, None
        if isAlign(idaapi.getFlags(cur_end)):
            # need to check for two types of alignment. The first is the 90 90.. or other recurring pattern
            # if the first two bytes don't match we can calculate the size of the alignment.
            abyte_check = idaapi.get_many_bytes(cur_end,2)
            # check if bytes match and if not 0. This could be changed to only check for 90 or CC
            if abyte_check[0] == abyte_check[1] and abyte_check[0] != "\x00":
                alignByte = idaapi.get_many_bytes(cur_end,1) 
                # loop through align bytes till end
                while idaapi.get_many_bytes(cur_end,1) == alignByte:
                    cur_end += 1
                if GetFunctionName(cur_end + 1) != "":
                    return None, None  
                else:
                    return cur_end, "align"
            else:
                distance = self.calc_dist(cur_end)
                # we can calculat the distance 
                cur_end += distance
                if GetFunctionName(cur_end) != "":
                    return None, None  
                else:
                    return cur_end, "align-c"
        # this is a sketchy check based off of 
        abyte_check = idaapi.get_many_bytes(cur_end,2)
        # check if bytes match and if not 0. This could be changed to only check for 90 or CC
        if abyte_check[0] == abyte_check[1] and  abyte_check[0] != "\x00":
            alignByte = abyte_check[0]
            while idaapi.get_many_bytes(cur_end,1) == alignByte:
                cur_end += 1
            # prev addr equals start of the next function     
            if GetFunctionName(cur_end + 1) != "":
                return None, None
            return cur_end, "align"
        # check if byte is code
        if isCode(idaapi.getFlags(cur_end)) and GetFunctionName(cur_end) == "":
            return cur_end, "code"
        # check if byte is data
        if isData(idaapi.getFlags(cur_end)):
           return cur_end, "data"
        # check if address is valid
        if cur_end == BADADDR:
            return None, None
        else:
            return cur_end, "unknown" 
            
    def check_up(self, func_addr):
        cur_func = idaapi.get_func(func_addr)
        cur_start = cur_func.startEA
        prev_addr = PrevHead(cur_start)        
        if prev_addr == BADADDR:
            return None, None
        # get start of the next function
        if GetFunctionName(prev_addr) != "":
            return None, None
        # quick check to see if from the end of the function
        # is an align byte
        tmp_prev = prev_addr
        for dist in range(0, 15):
            tmp_prev -= dist
            if isAlign(idaapi.getFlags(tmp_prev)):
                if GetFunctionName(tmp_prev-1) != "":
                    return None, None
                else:
                    return tmp_prev, "align"
        # check for align bytes that are static such as CC CC or 90 90
        abyte_check = idaapi.get_many_bytes(prev_addr,2)
        if abyte_check != None:
            if abyte_check[0] == abyte_check[1] and abyte_check[0] != "\x00":
                alignByte = abyte_check[0]
                while idaapi.get_many_bytes(prev_addr,1) == alignByte:
                    prev_addr -= 1
                # prev_addr equals end of the previous function
                if GetFunctionName(PrevHead(prev_addr)) != "":
                        return None, None
                else:
                    return prev_addr, "align"
        # check if byte is code
        if isCode(idaapi.getFlags(prev_addr)) and GetFunctionName(prev_addr) == "":
            return prev_addr, "code"
        # check if byte is data
        if isData(idaapi.getFlags(prev_addr)):
           return prev_addr, "data"
        # check if byte is ascii
        if isASCII(idaapi.getFlags(prev_addr)):
            return prev_addr, "ascii"
        # check if address is valid
        if prev_addr == BADADDR:
            return None, None
        else:
            # Warning: replace "prev_addr" with "None" if large amounts of FPs
            # Calculating the beginning of align bytes isn't the easiet thing. 
            return prev_addr, "unknown"      

    def populate_mods(self):
        self.getKnownFunctions()
        for addr in self.firstList:
            up = self.check_up(addr['start'])
            if None not in up:
                self.modList.append(["up", up[0], up[1]])
            down = self.check_down(addr['start'])
            if None not in down:
                self.modList.append(["down", down[0], down[1]])

    def print_all(self):
    # { "id":function_name, "start":function_start_addr, "end":function_end_addr
        for block in self.modList:
                end = FindFuncEnd(block[1])
                if end == BADADDR:
                    print "addr:%-8x from:%-4s type:%-5s Func End:Unknown" % (block[1],block[0], block[2])
                else:
                    print "addr:%-8x from:%-4s type:%-5s Func End:%x" % (block[1],block[0], block[2], end)                    

class analyze:
	# func = idaapi.get_next_func(here())
    def analysis_group(self):
         # align, code, data, ascii, align-c, unknown
        for block in self.modList:
            if block[0] == "up" and block[1] == "align":
                print 
            if block[0] == "down" and block[1] == "align":
                pass
            if block[0] == "up" and block[1] == "align-c":
                pass
            if block[0] == "down" and block[1] == "align-c":
                # if down align-c = pointer will be at the start of the code
                pass
            if block[0] == "up" and block[1] == "code":
                pass
            if block[0] == "down" and block[1] == "code":
                pass
            if block[0] == "up" and block[1] == "data":
                pass
            if block[0] == "down" and block[1] == "data":
                pass
            if block[0] == "up" and block[1] == "ascii":
                pass
            if block[0] == "down" and block[1] == "ascii":
                pass
            if block[0] == "up" and block[1] == "unknown":
                pass
            if block[0] == "down" and block[1] == "unknown":
                pass

    def test_mov_edi2_find(self, addr):
            'return the address of the next mov edi, edi. Distance needs to be validated' 
            if GetMnem(addr) == "mov" and GetOpnd(addr, 0) == "edi" and GetOpnd(addr, 1) == "edi":
                    mov_addr = FindBinary(addr +1, SEARCH_DOWN, "8B FF")
                    if mov_addr == BADADDR:
                            return None
                    else:
                            return mov_addr
            else:
                    return None
                    
    def inverse(self,addr):
            inverse = ""
            if GetMnem(addr) == "push" and GetOpnd(addr,0) == "esp":
                    inverse = "pop " + GetOpnd(addr,0)
            if GetMnem(addr) == "push" and GetOpType(addr, 0) == 1 and GetOpnd(addr,0) != "esp":
                    inverse = "pop " + GetOpnd(addr,0)
            if GetMnem(addr) == "sub"and GetOpnd(addr,0) == "esp":
                    inverse = "add " +  GetOpnd(addr,0) + ", " + hex(GetOperandValue(addr,1))[2:] + 'h'
            if  GetMnem(addr) == "add" and GetOpnd(addr,0) == "esp":
                    inverse = "sub " +  GetOpnd(addr,0) + ", " + GetDisasm(addr).split(",")[-1]
            if GetMnem(addr) == "mov" and GetOpnd(addr, 0) == "ebp" and GetOpnd(addr,1) == "esp":
                    # can be used to find the end of the function prologue
                    inverse = "mov ebp, esp"
            return inverse
			
				
    def find_align_ret(self, start, end):
            cur = start
            while(True):
                    if 'ret' in GetMnem(cur) :
                            if isAlign(idaapi.getFlags(NextAddr(cur))):
                                   return cur    
                    cur = NextAddr(cur)
                    if cur >= end:
                            return None           
        
if __name__ == '__main__':
   f = undefinder()
   f.populate_mods()
   f.print_all()
