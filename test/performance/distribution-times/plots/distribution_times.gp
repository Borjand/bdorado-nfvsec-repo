# ==========================================
# Boxplot EPS (gnuplot 6.0.4) - sample-like style
# Light blue boxes, grey whiskers, BLUE median line, X mean marker
# ==========================================

FILE2  = "../results/distribution_times_2_agents.csv"
FILE4  = "../results/distribution_times_4_agents.csv"
FILE8  = "../results/distribution_times_8_agents.csv"
FILE16 = "../results/distribution_times_16_agents.csv"
FILE32 = "../results/distribution_times_32_agents.csv"

MEANSFILE = "means_tmp.dat"

set terminal postscript eps enhanced color font "Helvetica,18"
set output "boxplot_agents_style.eps"

set title "Key distribution time"
set ylabel "Duration (ms)"

set datafile separator ";"
set datafile missing "NA"

set grid
set tics nomirror

set key top left
set key box opaque 
set key box lc rgb "black" lw .2
set key spacing 1.2
set key offset 1.2, -0.4


set xrange [0.5:5.5]
set xtics ("2 agents" 1, "4 agents" 2, "8 agents" 3, "16 agents" 4, "32 agents" 5)
set boxwidth 0.4

# --- Boxplot behaviour ---
set style data boxplot
set style boxplot nooutliers

# --- Colors ---
BOX_FILL  = "#AECBFA"   # light blue fill
EDGE_GREY = "#8A8A8A"   # whiskers/edges
MED_BLUE  = "#2F6FED"   # vivid blue median
RED  = "#800020"   # burgundy

# Fill + outlines/whiskers
set style fill solid 0.9 border lc rgb "black"
set border lc rgb "black"

# ---- Stats (column 5 = duration_ms), skip header (every ::1) ----
stats FILE2  using 5 every ::1 name "S2"  nooutput
stats FILE4  using 5 every ::1 name "S4"  nooutput
stats FILE8  using 5 every ::1 name "S8"  nooutput
stats FILE16 using 5 every ::1 name "S16" nooutput
stats FILE32 using 5 every ::1 name "S32" nooutput

MED2  = S2_median
MED4  = S4_median
MED8  = S8_median
MED16 = S16_median
MED32 = S32_median

MEAN2  = S2_mean
MEAN4  = S4_mean
MEAN8  = S8_mean
MEAN16 = S16_mean
MEAN32 = S32_mean

print sprintf("Median (2 agents)  = %.2f ms", MED2)
print sprintf("Median (4 agents)  = %.2f ms", MED4)
print sprintf("Median (8 agents)  = %.2f ms", MED8)
print sprintf("Median (16 agents) = %.2f ms", MED16)
print sprintf("Median (32 agents) = %.2f ms", MED32)

print sprintf("Mean (2 agents)  = %.2f ms", MEAN2)
print sprintf("Mean (4 agents)  = %.2f ms", MEAN4)
print sprintf("Mean (8 agents)  = %.2f ms", MEAN8)
print sprintf("Mean (16 agents) = %.2f ms", MEAN16)
print sprintf("Mean (32 agents) = %.2f ms", MEAN32)

# ---- Blue median lines (manual) ----
#set arrow 1 from 0.8,MED2  to 1.2,MED2  nohead front lw 3 lc rgb MED_BLUE
#set arrow 2 from 1.8,MED4  to 2.2,MED4  nohead front lw 3 lc rgb MED_BLUE
#set arrow 3 from 2.8,MED8  to 3.2,MED8  nohead front lw 3 lc rgb MED_BLUE
#set arrow 4 from 3.8,MED16 to 4.2,MED16 nohead front lw 3 lc rgb MED_BLUE
#set arrow 5 from 4.8,MED32 to 5.2,MED32 nohead front lw 3 lc rgb MED_BLUE
# --- write medians to file ---
set print "medians_tmp.dat"
print sprintf("1; %.6f", MED2)
print sprintf("2; %.6f", MED4)
print sprintf("3; %.6f", MED8)
print sprintf("4; %.6f", MED16)
print sprintf("5; %.6f", MED32)
set print

# ---- Means as X markers (write to file) ----
set print MEANSFILE
print sprintf("1; %.6f", MEAN2)
print sprintf("2; %.6f", MEAN4)
print sprintf("3; %.6f", MEAN8)
print sprintf("4; %.6f", MEAN16)
print sprintf("5; %.6f", MEAN32)
set print

DX = 0.40    # width of the median line (should match boxwidth)

# ---- Plot ----
plot \
  FILE2  using (1):($5) every ::1 lc rgb BOX_FILL notitle, \
  FILE4  using (2):($5) every ::1 lc rgb BOX_FILL notitle, \
  FILE8  using (3):($5) every ::1 lc rgb BOX_FILL notitle, \
  FILE16 using (4):($5) every ::1 lc rgb BOX_FILL notitle, \
  FILE32 using (5):($5) every ::1 lc rgb BOX_FILL notitle, \
  "medians_tmp.dat" using ($1-DX/2):2:(DX):(0) with vectors nohead lw 3 lc rgb MED_BLUE notitle, \
  MEANSFILE using 1:2 with points pt 3 ps 1 lc rgb RED notitle, \
  NaN with lines lw 3 lc rgb MED_BLUE title "Median", \
  NaN with points pt 3 ps 1 lc rgb RED title "Mean"
