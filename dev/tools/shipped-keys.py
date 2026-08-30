import re,sys
src=open('proxy/tropico_fix.c').read()
src=re.sub(r'/\*.*?\*/','',src,flags=re.S)          # code only
out=set()
for m in re.finditer(r'GetPrivateProfile(?:Int|String)A\("([A-Za-z]+)",\s*"([A-Za-z0-9_]+)",\s*([^,]+),',src):
    sec,key,dflt=m.group(1),m.group(2),m.group(3).strip()
    if dflt not in ('0','""','NULL'):
        out.add(f"[{sec}] {key}")
print("\n".join(sorted(out)))
