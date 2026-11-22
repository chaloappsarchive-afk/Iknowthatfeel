#!/usr/bin/env python3
"""Build a synthetic global-metadata.dat (v24.5 layout) to smoke-test the parser."""
import struct, sys

LEADING = ["stringLiteral","stringLiteralData","string","events","properties","methods",
           "parameterDefaultValues","fieldDefaultValues","fieldAndParameterDefaultValueData",
           "fieldMarshaledSizes","parameters","fields","genericParameters",
           "genericParameterConstraints","genericContainers","nestedTypes","interfaces",
           "vtableMethods","interfaceOffsets","typeDefinitions","images","assemblies"]

strings, heap = {}, bytearray()
def S(s):
    if s not in strings:
        strings[s] = len(heap); heap.extend(s.encode()+b"\0")
    return strings[s]

types = [("GameManager","",0x02000002),("BotController","ChickenGun.AI",0x02000003),
         ("ModMenu","",0x02000004),("String","",0x02000001)]
methods = [("Awake",0,0x06000001,0),("ClearBots",1,0x06000002,1),
           ("ClearBotsInternal",1,0x06000003,2),("SpawnBots",1,0x06000004,1),
           ("OnGUI",2,0x06000005,0),("ClearBots",2,0x06000006,0),
           ("IsNullOrEmpty",3,0x06000007,1)]
literals = ["Clear Bots","Remove all bots","bot_count","MainMenu"]

TYPEDEF_SZ, METHOD_SZ, IMAGE_SZ = 76, 32, 40
td_buf = bytearray(); md_buf = bytearray(); img_buf = bytearray()
lit_buf = bytearray(); litdata = bytearray()

# typeDefinitions: methodStart must be the running method index
starts, mi = {}, 0
for t in types:
    starts[mi] = t
    while mi < len(methods) and methods[mi][1] == types.index(t):
        mi += 1
for ti,(nm,ns,tok) in enumerate(types):
    mstart = next(i for i,(n,d,t,p) in enumerate(methods) if d==ti)
    rec = bytearray(TYPEDEF_SZ)
    struct.pack_into("<ii", rec, 0, S(nm), S(ns) if ns else -1)
    struct.pack_into("<i", rec, 40, mstart)
    struct.pack_into("<I", rec, TYPEDEF_SZ-8, tok)
    td_buf += rec
for i,(nm,decl,tok,pc) in enumerate(methods):
    rec = bytearray(METHOD_SZ)
    struct.pack_into("<iiiiii", rec, 0, S(nm), decl, 0, i, -1, tok)
    struct.pack_into("<HHHH", rec, 24, 0x86, 0, 0xFFFF, pc)
    md_buf += rec
for i,nm in enumerate(["Assembly-CSharp.dll","mscorlib.dll"]):
    rec = bytearray(IMAGE_SZ); struct.pack_into("<ii", rec, 0, S(nm), i)
    struct.pack_into("<ii", rec, 8, i*2, 2)
    img_buf += rec
for s in literals:
    b = s.encode(); lit_buf += struct.pack("<Ii", len(b), len(litdata)); litdata += b

blobs = {"stringLiteral":bytes(lit_buf),"stringLiteralData":bytes(litdata),
         "string":bytes(heap),"methods":bytes(md_buf),
         "typeDefinitions":bytes(td_buf),"images":bytes(img_buf)}
hdr_size = 8 + len(LEADING)*8
body_start = (hdr_size + 15) & ~15
pairs = {}
body = bytearray(body_start - hdr_size)      # padding up to the aligned body start
for name in LEADING:
    data = blobs.get(name, b"")
    while len(body) % 4: body.append(0)
    pairs[name] = (hdr_size + len(body), len(data)); body += data
out = bytearray(hdr_size)
struct.pack_into("<Ii", out, 0, 0xFAB11BAF, 24)
for i,name in enumerate(LEADING):
    o,s = pairs[name]; struct.pack_into("<ii", out, 8+i*8, o, s)
out += body
open(sys.argv[1] if len(sys.argv)>1 else "/tmp/fake-global-metadata.dat","wb").write(bytes(out))
print("wrote", len(out), "bytes; methods:", len(methods), "types:", len(types))
