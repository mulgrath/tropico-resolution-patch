import sys, importlib.util, os
S=os.path.dirname(os.path.abspath(__file__))
spec=importlib.util.spec_from_file_location('fo','/home/mulgrath/dev/tropico-resolution-patch/dev/probes/font_oracle.py')
fo=importlib.util.module_from_spec(spec); sys.argv=['x']; spec.loader.exec_module(fo)
lib35=fo.ft_library(35); lib40=fo.ft_library(40)
CC=os.environ.get('CC_DIR', os.path.expanduser('~'))   # CopperplateCC-{Bold,Heavy}.ttf from github.com/CowboyCollective/CopperplateCC (OFL); not in the repo
faces={'ccbold':CC+'/CopperplateCC-Bold.ttf','ccheavy':CC+'/CopperplateCC-Heavy.ttf'}
for asset in ['copp6','copp8','copp10','copp12']:
    glyphs=fo.load_asset(asset)
    for key,path in faces.items():
        fd=dict(f35=fo.Face(lib35,path), f40=fo.Face(lib40,path))
        for mode in fo.MODES:
            r=fo.best_fit(glyphs,key,fd,mode,range(4,80),refine=True,phase_search=True)
            if r is None: continue
            p,s,m=r
            print(f"{asset} {key:8s} {mode[0]:11s} ppem {p:6.2f} n {s['n']:3d} cell= {s['cell_exact']*100:4.0f}% dw,dh {s['mean_adw']:.2f},{s['mean_adh']:.2f} adv {s['dadv_med']:+.1f}±{s['dadv_sd']:.1f} fit {s['cfit_med']:.3f}/{s['cfit_p05']:.3f}/{s['cfit_min']:.3f} cov {s['cov_med']:.2f}", flush=True)
