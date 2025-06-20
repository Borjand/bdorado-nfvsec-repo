#!/bin/bash

# Verificación de argumentos
if [ -z "$1" ]; then
  echo "Uso: $0 <nombre-parcial-del-pod>"
  exit 1
fi

POD_NAME_PARTIAL="$1"

# Obtener el ID del contenedor desde el nombre del pod
CONTAINER_ID=$(sudo microk8s ctr containers ls | grep "$POD_NAME_PARTIAL" | awk '{print $1}' | head -n 1)

if [ -z "$CONTAINER_ID" ]; then
  echo "No se encontró ningún contenedor con nombre que coincida con: $POD_NAME_PARTIAL"
  exit 1
fi

echo "[+] Contenedor encontrado: $CONTAINER_ID"

# Obtener el PID del contenedor
PID=$(sudo microk8s ctr task ls | grep "$CONTAINER_ID" | awk '{print $2}')

if [ -z "$PID" ]; then
  echo "No se pudo obtener el PID del contenedor"
  exit 1
fi

echo "[+] PID del contenedor: $PID"

# Obtener el índice de la interfaz de red (por ejemplo: eth0@if4)
IFINDEX=$(sudo nsenter -t "$PID" -n ip link show eth0 | grep '@if' | sed -n 's/.*@if\([0-9]\+\):.*/\1/p')

if [ -z "$IFINDEX" ]; then
  echo "No se pudo encontrar el índice de la interfaz de red"
  exit 1
fi

# Encontrar la interfaz del host con ese índice
HOST_IF=$(ip link | grep "^$IFINDEX:" | awk -F: '{print $2}' | tr -d ' ')

if [ -z "$HOST_IF" ]; then
  echo "No se pudo encontrar la interfaz del host correspondiente al pod"
  exit 1
fi

echo "[+] Interfaz del host: $HOST_IF"

# Lanzar tcpdump
#echo "[+] Ejecutando tcpdump en la interfaz $HOST_IF (puerto 9092)..."
#sudo tcpdump -i "$HOST_IF" port 9092 -nn
