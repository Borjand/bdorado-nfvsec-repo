# Script to add static routes on the pods after macsec configuration
#!/bin/bash

NAMESPACE="8e05312c-c696-4fe9-9df9-e389ff126dde"
CONTAINER="sec-agent" 
ROUTE_COMMAND="ip route add 10.98.0.0/24 via 10.78.0.10"

PODS=(
  haproxy-lb
  web-server-0
  web-server-1
  web-server-2
)

# Routes through router
for POD in "${PODS[@]}"; do
  echo "➤ Añadiendo ruta en pod: $POD"
  kubectl exec -n "$NAMESPACE" "$POD" -c "$CONTAINER" -- bash -c "$ROUTE_COMMAND"
done

# Static route for router through the GRE tunnel
POD=router
ROUTE_COMMAND="ip route add 10.98.0.0/24 via 10.0.0.12"
echo "➤ Añadiendo ruta en pod: $POD"
kubectl exec -n "$NAMESPACE" "$POD" -c "$CONTAINER" -- bash -c "$ROUTE_COMMAND"

