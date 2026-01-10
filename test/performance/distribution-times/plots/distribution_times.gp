# ===============================
# Boxplot EPS + mediana en azul (gnuplot 6.0.4)
# ===============================

FILE = "../results/distribution_times_2_agents.csv"
FILE4 = "../results/distribution_times_4_agents.csv"
FILE8 = "../results/distribution_times_8_agents.csv"
FILE16 = "../results/distribution_times_16_agents.csv"
FILE32 = "../results/distribution_times_32_agents.csv"

set terminal postscript eps enhanced color font "Helvetica,18"
set output "boxplot_agents.eps"

set title "Key distribution time (2 sec-agents)"
set ylabel "Duration (ms)"

set datafile separator ";"
unset key
set grid

# Una sola caja centrada en x=1
set xrange [0.5:5.5]
set xtics ("2 agents" 1, "4 agents" 2, "8 agents" 3, "16 agents" 4, "32 agents" 5)
set boxwidth 0.4

#set style fill solid 0.5 border -1
#set style line 1 lc rgb "#AECBFA"
set style data boxplot 
set style boxplot nooutliers

# Calcular mediana (columna 5), saltando la cabecera (every ::1)
stats FILE using 5 every ::1 name "S" nooutput
MED = S_median
stats FILE4 using 5 every ::1 name "S4" nooutput
MED4 = S4_median
stats FILE8 using 5 every ::1 name "S8" nooutput
MED8 = S8_median
stats FILE16 using 5 every ::1 name "S16" nooutput
MED16 = S16_median
stats FILE32 using 5 every ::1 name "S32" nooutput
MED32 = S32_median

print sprintf("Median (2 agents) = %.2f ms", MED)
print sprintf("Median (4 agents) = %.2f ms", MED4)
print sprintf("Median (8 agents) = %.2f ms", MED8)
print sprintf("Median (16 agents) = %.2f ms", MED16)
print sprintf("Median (32 agents) = %.2f ms", MED32)

# Dibujar una línea azul vivo encima de la mediana
# (ajusta los x para que cubra el ancho de la caja)
#set arrow 1 from 0.8,MED to 1.2,MED nohead front lw 4 lc rgb "#0066FF"
#set arrow 2 from 1.8,MED4 to 2.2,MED4 nohead front lw 4 lc rgb "#0066FF"
#set arrow 3 from 2.8,MED8 to 3.2,MED8 nohead front lw 4 lc rgb "#0066FF"

#plot FILE using (1):5 every ::1 notitle lc rgb "#000000"
#plot FILE using (1):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1
plot \
    FILE using (1):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1, \
    FILE4 using (2):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1, \
    FILE8 using (3):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1, \
    FILE16 using (4):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1, \
    FILE32 using (5):5 every ::1 notitle lc rgb "#0066FF" fillstyle solid 0.1