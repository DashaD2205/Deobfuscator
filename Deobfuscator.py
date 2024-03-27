from time import *

adrr_list = []
important = ["ENDBR64", "PUSH RBP", "MOV RBP,RSP", "SUB RSP,0x10", "RET", "LEAVE"]
registr = dict()
stack = []
trash = ["NOP"]
instructions_deob = []
instructions_deob_1 = []
callsy = ["0x001008d0", "0x001008f0", "0x00101050", "0x00100870", "0x00100860"]
symbols = set(currentProgram.getFunctionManager().getFunctionsNoStubs(True))
print('Hi there, here is the script that was made to deobfuscate functions in binary file. Having previously deobfuscated them.')
print('EMPTY mark - means that this function is empty and you should just skip it')
print('ONLY CALL mark - means that this function is just calling another function and you should just skip it')
print('OKAY mark - means that this function is not empty and can be significant')
print('')
sleep(8)
def get_function_by_name(function_name):
    current_program = getCurrentProgram()
    function_manager = current_program.getFunctionManager()
    for function in function_manager.getFunctions(True):
        if function.getName() == function_name:
            return function

    return None
def print_function_contents(function):
    global adrr_list
    if function is None:
        return
    body = function.getBody()
    for instr in body:
        adrr_list = list(instr)
        return list(instr)
        break

function_name = "main"
found_function = get_function_by_name(function_name)
if found_function:
    print_function_contents(found_function)
else:
    print("Function not found with name: " + function_name)
def disassemble_range(start_addr, end_addr):
    gg = []
    current_program = getCurrentProgram()
    listing = current_program.getListing()

    current_addr = start_addr
    while current_addr <= end_addr:
        instruction = listing.getInstructionAt(current_addr)
        if instruction:
            gg.append(instruction)
            current_addr = current_addr.add(instruction.getLength())
        else:
            print("Invalid instruction at address: " + str(current_addr))
            break
    return list(gg)
start_address = adrr_list[0]
end_address = adrr_list[-1]
disassemble_range(start_address, end_address)
def get_asm_code():
    f = open('output.txt', 'w')
    for instr in currentProgram.getListing().getInstructions(True):
        f.write("\" " + str(instr) + "\\n\\t" + "\"")
    f.close()

def get_functions_st_en(symbols):
    aksolotl = []
    for s in symbols:
       e = print_function_contents(s)
       aksolotl.append(e[0])
    return aksolotl
def simple_sintaksis_deobf(func_name):
    found_function = get_function_by_name(func_name)
    e = print_function_contents(found_function)
    for i in disassemble_range(e[0], e[-1]):
        if str(i) in trash:
            continue
        elif str(i) in important:
            instructions_deob.append(str(i))
            continue
        elif str(i).split(' ')[0] == 'MOV':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    if cdr == strk:
                        continue
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num})
        elif str(i).split(' ')[0] == 'ADD':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num + registr[(strk)]})
        elif str(i).split(' ')[0] == 'XOR':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num & registr[(strk)]})
        elif str(i).split(' ')[0] == 'SUB':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num - registr[(strk)]})
        elif str(i).split(' ')[0] == 'IMUL':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num * registr[(strk)]})
        elif str(i).split(' ')[0] == 'LEA':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0
            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                cdr = cdr.split('[')[0]
                cdr = cdr.split(']')[0]
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            try:
                regq = registr[(strk)]
            except:
                registr.update({strk:0})
                regq = 0         
            registr.update({strk:num + regq})
        elif str(i).split(' ')[0] == 'DIV':
            our_instr = str(i).split(' ')
            strk = our_instr[1].split(',')[0]
            try:
               our_instr.remove('dword')
            except:
                gfh = 0
            try:
               our_instr.remove('qword')
            except:
                gfh = 0

            try:
               our_instr.remove('ptr')
               strk = our_instr[1]
               if '[' in strk:
                   strk += (' ' + our_instr[2])
                   strk += (' ' + our_instr[3].split(',')[0])
                   cdr = our_instr[3].split(',')[1]
            except:
                cdr = our_instr[1].split(',')[1]
            try:
                num = int(cdr, 16)
            except:
                try:
                    num = registr[(cdr)]
                except:
                    registr.update({cdr:0})
                    num = 0
            registr.update({strk:num // registr[(strk)]})
        elif str(i).split(' ')[0] == 'PUSH':
            our_instr = str(i).split(' ')
            try:
                num = int(our_instr[1], 16)
            except:
                instructions_deob.append('MOV ' + (our_instr[1]) + ',' + hex(registr[(our_instr[1])]))
                instructions_deob_1.append(str(i))
                num = registr[(our_instr[1])]
            stack.append(num)
            instructions_deob.append(str(i))
        elif str(i).split(' ')[0] == 'POP':
            our_instr = str(i).split(' ')
            strk = our_instr[1]
            try:
                num = stack.pop()
            except:
                num = 0
            registr.update({strk:num})
        elif str(i).split(' ')[0] == 'CALL':
            if str(i).split(' ')[1] not in callsy:
                instructions_deob.append(str(i))
                instructions_deob_1.append(str(i))
            else:
                for j in list(registr.keys()):
                    try:
                        if registr[j] != 0: 
                            instructions_deob.append('MOV ' + j + ',' + hex(registr[j]))
                            instructions_deob_1.append('MOV ' + j + ',' + hex(registr[j]))
                    except:
                        continue
                instructions_deob.append(str(i))
                instructions_deob_1.append(str(i))
                        
        else:
            instructions_deob.append(str(i))
            instructions_deob_1.append(str(i))
        num = 0
    return [instructions_deob, instructions_deob_1]
def find_trash_funcs(i):
    try:
        dew = simple_sintaksis_deobf(str(i))
    except:
        return
    if len(dew[1]) == 1:
        if (dew[1])[0].split(' ')[0] == "CALL":
            print('-------------------------------------------------------')
            print('')
            print(str(i) + ' ---> ONLY CALL')
            print('')
            for i in dew[0]:
                print(i)
            print('')
            return
    elif len(dew[1]) == 0:
        print('-------------------------------------------------------')
        print('')
        print(str(i) + ' ---> EMPTY')
        print('')
        for i in dew[0]:
                print(i)
        print('')
        return
    else:
        print('-------------------------------------------------------')
        print('')
        print(str(i) + ' ---> OKAY')
        print('')
        for i in dew[0]:
                print(i)
        print('')
        return
for i in symbols:     
    find_trash_funcs(i)
    instructions_deob = []
    instructions_deob_1 = []









