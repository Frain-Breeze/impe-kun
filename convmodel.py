import struct
import sys
import os

#"H:\ggr_out\GalGun Returns\Data\Common\d5b11002__CGAssets\94ee72fa__mdl\944835c3\f0431264\6c7ceba0.0.bin.decompressed.bin"
#"783fa148.400.bin.decompressed.bin"
#"H:/ggr_out/GalGun Returns/Data/Common/d5b11002__CGAssets/94ee72fa__mdl/944835c3/f0431264/0c111fff.0.bin.decompressed.bin"
#"H:/ggr_out/GalGun Returns/Data/Common/d5b11002__CGAssets/94ee72fa__mdl/94ed8c33__map/31084c97.0.bin.decompressed.bin"

total_faces = 0
swapped = True
index_offset = 0

def unwrapStrip(elements, fo):
    global swapped
    global total_faces
    global index_offset

    if len(elements) >= 2:
        a = elements[0]
        b = elements[1]
        
        for c in elements[2:]:
        
            towrite = "f "
            
            if swapped:
                towrite += str(index_offset+a+1) + "/" + str(index_offset+a+1) + "/" + str(index_offset+a+1) + " "
                towrite += str(index_offset+b+1) + "/" + str(index_offset+b+1) + "/" + str(index_offset+b+1) + " "
                towrite += str(index_offset+c+1) + "/" + str(index_offset+c+1) + "/" + str(index_offset+c+1) + "\n"
            else:
                towrite += str(index_offset+a+1) + "/" + str(index_offset+a+1) + "/" + str(index_offset+a+1) + " "
                towrite += str(index_offset+c+1) + "/" + str(index_offset+c+1) + "/" + str(index_offset+c+1) + " "
                towrite += str(index_offset+b+1) + "/" + str(index_offset+b+1) + "/" + str(index_offset+b+1) + "\n"
                #towrite = ""
            
            a = b
            b = c
            
            if swapped:
                swapped = False
            else:
                swapped = True
            
            total_faces+=1
            fo.write(towrite)
    elements.clear()

def processEntry(fi, fo):
    global total_faces
    global swapped
    global index_offset
    
    fi.seek(fi.tell() + 16)
    size = struct.unpack('I', fi.read(4))[0]
    fi.seek(fi.tell() + 12)
    
    
    elements = []
    highest_vert_index = -1
    last = -1
    group_size = 0
    total_faces = 0
    swapped = True
    
    
    is_big = False
    i = size / 2
    if struct.unpack('I', fi.read(4))[0] == 0:
        is_big = True
        i = size / 4
    fi.seek(fi.tell() - 4)
    
    while i > 0:
        new = 0
        if is_big:
            new = struct.unpack('I', fi.read(4))[0]
        else:
            new = struct.unpack('H', fi.read(2))[0]
        
        if new > highest_vert_index:
            highest_vert_index = new
        
        if new == last:
            print(str(group_size) + " ", end="")
            group_size = 0
        
        if group_size == 0 and len(elements) > 0:
            unwrapStrip(elements, fo)
        
        elements.append(new)
        group_size += 1
        
        last = new
        
        i -= 1
    
    if group_size != 0:
        print(str(group_size) + " ", end="")
        unwrapStrip(elements, fo)
        
    index_offset += highest_vert_index + 1
    
    print("total faces: " + str(total_faces))
    
    while fi.tell() % 16:
        fi.seek(fi.tell() + 1)
    
    i = highest_vert_index + 1
    print("vertex pairs: " + str(i))
    while i > 0:
        fo.write("v ")
        poyo = struct.unpack('fff', fi.read(12))
        fo.write(str(poyo[0]))
        fo.write(" ")
        fo.write(str(poyo[1]))
        fo.write(" ")
        fo.write(str(poyo[2]))
        fo.write("\n")
        i -= 1
    
    i = highest_vert_index + 1
    while i > 0:
        fo.write("vn ")
        poyo = struct.unpack('fff', fi.read(12))
        fo.write(str(poyo[0]))
        fo.write(" ")
        fo.write(str(poyo[1]))
        fo.write(" ")
        fo.write(str(poyo[2]))
        fo.write("\n")
        i -= 1
    
    #fi.read(12 * (highest_vert_index + 1))
    
    i = highest_vert_index + 1
    while i > 0:
        fo.write("vt ")
        poyo = struct.unpack('ff', fi.read(8))
        fo.write(str(poyo[0]))
        fo.write(" ")
        fo.write(str(1 - poyo[1]))
        fo.write("\n")
        i -= 1
    
if len(sys.argv) == 3:
    with open(sys.argv[1], "rb") as fi, open(sys.argv[2], "w") as fo:
        magic = struct.unpack('I', fi.read(4))[0]
        if magic != 0x14:
            print("not the correct magic! abandoning")
            sys.exit()
        fi.seek(24)
        size_of_curr_module = struct.unpack('I', fi.read(4))[0]
        print("size of curr module: " + str(size_of_curr_module))
        fi.seek(40)
        entry_count = struct.unpack('I', fi.read(4))[0]
        for i in range(entry_count):
            fi.seek(44 + (80 * i))
            print("thing " + str(44 + (80 * i)))
            entry_offset = struct.unpack('I', fi.read(4))[0]
            fi.seek(entry_offset + 32)
            print(fi.tell())
            fo.write("o " + os.path.basename(sys.argv[2]) + "_" + str(i) + "\n")
            processEntry(fi, fo)

#with open("783fa148.400.bin.decompressed.bin", "rb") as fi, open("out.obj", "w") as fo:
#    
#    fi.seek(204)
#    #fi.seek(124)
#    offset = struct.unpack('I', fi.read(4))[0]
#    fi.seek(offset + 16 + 32)
#    size = struct.unpack('I', fi.read(4))[0]
#    fi.seek(offset + 32 + 32)
#    
#    print("offset is " + str(offset))
#    print("size is " + str(size))
#    
#    old_offset = fi.tell()
#    
#    fi.seek(old_offset)
#    i = (size / 2)
#    
#    elements = []
#    
#    highest_vert_index = -1
#    
#    last = -1
#    group_size = 0
#    
#    while i > 0:
#        new = struct.unpack('H', fi.read(2))[0]
#        
#        if new > highest_vert_index:
#            highest_vert_index = new
#        
#        if new == last:
#            #if group_size == 2:
#            #    towrite = ""
#            print(str(group_size) + " ", end="")
#            group_size = 0
#        
#        if group_size == 0 and len(elements) > 0:
#            lolibaaba(elements, fo)
#        
#        elements.append(new)
#        group_size += 1
#        
#        last = new
#        
#        i -= 1
#    
#    if group_size != 0:
#        print(str(group_size) + " ", end="")
#        lolibaaba(elements, fo)
#    
#    fi.seek(size + old_offset)
#    
#    print("total faces: " + str(total_faces))
#
#    while fi.tell() % 16:
#        fi.seek(fi.tell() + 1)
#    
#    #ii = ((230080 / 3) / 12)
#    ii = highest_vert_index + 1
#    print("beep boop " + str(fi.tell()))
#    print("beep boop end " + str(fi.tell() + (ii * 12)))
#    #fi.read(ii * 8)
#    print("vertex pairs: " + str(ii))
#    #ii = (3000 / 12)
#    while ii > 0:
#        fo.write("v ")
#        poyo = struct.unpack('fff', fi.read(12))
#        fo.write(str(poyo[0]))
#        fo.write(" ")
#        fo.write(str(poyo[1]))
#        fo.write(" ")
#        fo.write(str(poyo[2]))
#        fo.write("\n")
#        ii -= 1
#    
#    ii = highest_vert_index + 1
#    #fi.read(ii * 12 * 1)
#    
#    while ii > 0:
#        fo.write("vn ")
#        poyo = struct.unpack('fff', fi.read(12))
#        fo.write(str(poyo[0]))
#        fo.write(" ")
#        fo.write(str(poyo[1]))
#        fo.write(" ")
#        fo.write(str(poyo[2]))
#        fo.write("\n")
#        ii -= 1
#    
#    ii = highest_vert_index + 1
#    
#    while ii > 0:
#        fo.write("vt ")
#        poyo = struct.unpack('ff', fi.read(8))
#        fo.write(str(poyo[0]))
#        fo.write(" ")
#        fo.write(str(1 - poyo[1]))
#        fo.write("\n")
#        ii -= 1
#    #while ii > 0:
#    #    fo.write("v ")
#    #    poyo = struct.unpack('ffff', fi.read(16))
#    #    fo.write(str(poyo[0]))
#    #    fo.write(" ")
#    #    fo.write(str(poyo[1]))
#    #    fo.write(" ")
#    #    fo.write(str(poyo[2]))
#    #    fo.write("\n")
#    #    ii -= 1
#    
#    
#    
#    
#    
#    
    