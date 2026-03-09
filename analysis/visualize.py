#!/usr/bin/env python3
"""
MEGALODON P2 — Visualize scan results
Usage: python3 analysis/visualize.py results/findings.csv
"""
import sys, os, csv
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("pip3 install matplotlib numpy")
    sys.exit(1)

C_BG='#0a0a0f'; C_GRID='#1a1a2e'; C_TEXT='#c0c0d0'
SEV_COLORS = {'CRITICAL':'#ff3366','HIGH':'#ff9933','MEDIUM':'#33ccff','LOW':'#c0c0d0'}

def style(ax):
    ax.set_facecolor(C_BG)
    ax.tick_params(colors=C_TEXT)
    ax.xaxis.label.set_color(C_TEXT); ax.yaxis.label.set_color(C_TEXT)
    ax.title.set_color(C_TEXT)
    for s in ax.spines.values(): s.set_color(C_GRID)

def main():
    if len(sys.argv)<2:
        print(f"Usage: {sys.argv[0]} <findings.csv>")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    outdir = os.path.dirname(csv_path) or '.'
    
    rows=[]
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    
    if not rows:
        print("No findings to visualize.")
        sys.exit(0)
    
    # Count by app and severity
    apps={}
    for r in rows:
        app=r['app']
        sev=r['severity']
        if app not in apps: apps[app]={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
        apps[app][sev]+=1
    
    # Stacked bar chart
    fig,ax=plt.subplots(figsize=(12,6))
    fig.patch.set_facecolor(C_BG); style(ax)
    
    app_names=list(apps.keys())
    x=np.arange(len(app_names))
    width=0.6
    
    bottom=np.zeros(len(app_names))
    for sev in ['LOW','MEDIUM','HIGH','CRITICAL']:
        vals=[apps[a][sev] for a in app_names]
        ax.bar(x,vals,width,bottom=bottom,label=sev,color=SEV_COLORS[sev],edgecolor='white',linewidth=0.5)
        bottom+=np.array(vals)
    
    ax.set_xticks(x)
    ax.set_xticklabels(app_names,rotation=25,ha='right',fontsize=10,color=C_TEXT)
    ax.set_ylabel('Secrets Found')
    ax.set_title('MEGALODON P2 — Secrets Found by Application',fontsize=14,fontweight='bold')
    ax.legend(facecolor=C_BG,edgecolor=C_GRID,labelcolor=C_TEXT)
    
    fig.tight_layout()
    out=os.path.join(outdir,'findings_by_app.png')
    fig.savefig(out,dpi=150,facecolor=C_BG)
    plt.close()
    print(f"[*] {out}")
    
    # Severity pie chart
    fig,ax=plt.subplots(figsize=(8,8))
    fig.patch.set_facecolor(C_BG)
    
    sev_totals={s:sum(apps[a][s] for a in apps) for s in ['CRITICAL','HIGH','MEDIUM','LOW']}
    sev_totals={k:v for k,v in sev_totals.items() if v>0}
    
    colors=[SEV_COLORS[s] for s in sev_totals.keys()]
    wedges,texts,autotexts=ax.pie(
        sev_totals.values(),labels=sev_totals.keys(),
        colors=colors,autopct='%1.0f%%',startangle=90,
        textprops={'color':C_TEXT,'fontsize':12}
    )
    for t in autotexts: t.set_color('white'); t.set_fontweight('bold')
    
    ax.set_title('MEGALODON P2 — Findings by Severity',fontsize=14,fontweight='bold',color=C_TEXT)
    
    out=os.path.join(outdir,'severity_distribution.png')
    fig.savefig(out,dpi=150,facecolor=C_BG)
    plt.close()
    print(f"[*] {out}")

if __name__=='__main__': main()
