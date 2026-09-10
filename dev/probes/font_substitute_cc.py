"""Build replacement coppN.i16 font containers from Copperplate CC Bold at a given scale.
Cell geometry (advance, baseline) is the plain resample's; the ink is the outline at ppem*s.
usage: gen_cc.py OUTDIR SCALE asset=ppem [asset=ppem ...]"""
import sys, os, struct, importlib.util
import numpy as np
S=os.path.dirname(os.path.abspath(__file__))
ROOT='/home/mulgrath/dev/tropico-resolution-patch'
spec=importlib.util.spec_from_file_location('fo',ROOT+'/dev/probes/font_oracle.py')
fo=importlib.util.module_from_spec(spec); _argv=sys.argv; sys.argv=['x']; spec.loader.exec_module(fo); sys.argv=_argv
hs, ar = fo.hs, fo.ar
FONT=os.environ.get('CC_FONT', os.path.expanduser('~/CopperplateCC-Bold.ttf'))   # github.com/CowboyCollective/CopperplateCC (OFL); not in the repo
MODE=[m for m in fo.MODES if m[0]=='ss4-v35'][0]
name, libkey, flags, ss, mono = MODE
lib=fo.ft_library(35)
face=fo.Face(lib, FONT)
from ctypes import Structure, c_long, byref, POINTER, c_void_p
class FT_Matrix(Structure): _fields_=[('xx',c_long),('xy',c_long),('yx',c_long),('yy',c_long)]
fo._ft.FT_Set_Transform.argtypes=[POINTER(fo.FT_FaceRec), c_void_p, POINTER(fo.FT_Vector)]
XSCALE=[1.0]
_orig_set_transform=fo._ft.FT_Set_Transform
def _patched(facep, mat, delta):
    m=FT_Matrix(int(round(XSCALE[0]*65536)),0,0,65536)
    return _orig_set_transform(facep, byref(m), delta)
fo._ft.FT_Set_Transform=_patched

def fit_xscale(asset, s, ppem):
    # median over A-Z 0-9 of resample advance / natural advance
    d=open(os.path.join(fo.ASSETS, asset+'.i16'),'rb').read(); r=hs.parse(d)
    XSCALE[0]=1.0; face.set_ppem(ppem*s, ss)
    ratios=[]
    for sp in r['sprites']:
        code=sp['index']+32
        if not (65<=code<=90 or 48<=code<=57): continue
        rr=face.render(code, flags, ss=ss, mono=mono, phase=(0.0,0.5))
        if rr is None: continue
        img,left,top,adv=rr
        want=int(round((sp['x']+sp['w'])*s))          # resample's advance edge
        have=left+img.shape[1]                         # natural ink right edge
        ratios.append(want/have)
    print(asset,'advance ratio p10/p50/min', round(float(np.percentile(ratios,10)),3), round(float(np.median(ratios)),3), round(min(ratios),3))
    return float(np.percentile(ratios,10))

def smallcap_ratio(asset):
    # stock small-cap ink height over cap ink height, median over the letters present
    ink={c:h for (c,x,y,w,h,g,adv) in fo.load_asset(asset)}
    r=[ink[c]/ink[c-32] for c in range(97,123) if c in ink and c-32 in ink and ink[c]>1]
    return float(np.median(r)) if r else 0.0

def build(asset, s, ppem):
    d=open(os.path.join(fo.ASSETS, asset+'.i16'),'rb').read()
    r=hs.parse(d); assert r['exact']
    sc=smallcap_ratio(asset); print(asset,'small-cap ratio',round(sc,3))
    xs=fit_xscale(asset, s, ppem); XSCALE[0]=min(1.0, xs)
    face.set_ppem(ppem*s, ss)
    out=bytearray(d[:r['table_base']]); table=[bytearray(t) for t in r['table']]; blocks=[]
    stats=dict(xscale=round(XSCALE[0],3), glyphs=0, fallback=[], clipped=0, clip_px=0)
    for sp in r['sprites']:
        if sp['fmt']!=2 or sp['w']==0 or sp['h']==0 or (sp['w']<=1 and sp['h']<=1):
            payload=bytes(d[sp['data_offset']:sp['data_offset']+sp['size']]); nw,nh,nx,ny=sp['w'],sp['h'],sp['x'],sp['y']
        else:
            nw=max(1,int(round(sp['w']*s))); nh=max(1,int(round(sp['h']*s)))
            nx=int(round(sp['x']*s)); ny=int(round(sp['y']*s))
            code=sp['index']+32
            lower = (97<=code<=122 or 224<=code<=255) and code not in (247,)
            if lower and sc>0:
                face.set_ppem(ppem*s*sc, ss)
                rr=face.render(code-32, flags, ss=ss, mono=mono, phase=(0.0,0.5))   # the capital, small
                face.set_ppem(ppem*s, ss)
            else:
                rr=face.render(code, flags, ss=ss, mono=mono, phase=(0.0,0.5))
            if rr is None:
                payload=ar.rescale_font_sprite(d, sp, nw, nh); stats['fallback'].append(chr(code) if 32<=code<127 else hex(code))
            else:
                img,left,top,adv=rr
                x0=min(nx,left); y0=min(ny,-top); x1=nx+nw; y1=max(ny+nh, -top+img.shape[0])
                W,H=x1-x0,y1-y0
                grid=np.zeros((H,W),np.float32)
                cx,cy=left-x0,-top-y0
                if cx+img.shape[1]>W:                  # slide left before clipping
                    cx=max(0, W-img.shape[1])
                cw=min(img.shape[1], W-cx)
                if cw<img.shape[1] and (img[:,cw:]>64).any():
                    stats['clipped']+=1; stats['clip_px']+=int((img[:,cw:]>64).sum()); stats.setdefault('who',[]).append((chr(code) if code<128 else bytes([code]).decode('cp1252'), int((img[:,cw:]>64).sum())))
                grid[cy:cy+img.shape[0], cx:cx+cw]=img[:,:cw]
                rows=[[ar.to_alpha(int(round(float(v)))) for v in line] for line in grid]
                pl=bytearray()
                for i,line in enumerate(rows):
                    pl+=hs.emit_row(line, term=None if i==H-1 else 0x00)
                pl.append(0xC0); payload=bytes(pl)
                nx,ny,nw,nh=x0,y0,W,H; stats['glyphs']+=1
            hs.check(payload,nw,nh,sp['index'])
        blocks.append(struct.pack('<IhhHHB',len(payload),nx,ny,nw,nh,sp['fmt'])+payload)
        struct.pack_into('<II',table[sp['index']],7,len(payload),len(payload))
    for t in table: out+=t
    for b in blocks: out+=b
    for i in range(7): struct.pack_into('<I',out,0x23+4*i,len(out))
    return bytes(out), stats

if __name__=='__main__':
    outdir=sys.argv[1]; s=float(sys.argv[2]); os.makedirs(outdir,exist_ok=True)
    for a in sys.argv[3:]:
        asset,ppem=a.split('='); data,st=build(asset,s,float(ppem))
        hs.parse(data)
        open(os.path.join(outdir,asset+'.i16'),'wb').write(data)
        print(asset, len(data), 'bytes', st)
