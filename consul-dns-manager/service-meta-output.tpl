{{- $DNS_PROVIDER_NAME := mustEnv "DNS_PROVIDER_NAME" -}}
{{- $SERVICE_NAME_REGEX := mustEnv "SERVICE_NAME_REGEX" -}}
{{- $COMBINED_REGEX := printf "%s%s" $SERVICE_NAME_REGEX $DNS_PROVIDER_NAME -}}

{{- /* Common fields shared across all providers */ -}}
{{- $commonFields := sprig_list
    "check_target"
    "config_hash"
    "dns_provider"
    "fallback_ip"
    "on_all_fail"
    "quorum"
    "record"
    "site"
    "ttl"
    "uplink_provider"
    "zone"
-}}

[
{{- $firstBlock := true -}}
{{- range $service := services -}}
{{- if $service.Name | regexMatch $COMBINED_REGEX -}}
    {{- $svc := $service.Name -}}
    {{- $all := service (print $svc "|any") -}}
    {{- if gt (len $all) 0 -}}

    {{- /* 1. Calculate unique nodes (by .Node) and nodes running an active serfHealth check.
            scratch.MapSet organizes a per-service map representation, where len(MapValues) details unique entries. */ -}}
    {{- range $n := $all -}}
        {{- scratch.MapSet (printf "total|%s" $svc) $n.Node true -}}
        {{- range $c := $n.Checks -}}
        {{- if and (eq $c.CheckID "serfHealth") (eq $c.Status "passing") -}}
            {{- scratch.MapSet (printf "alive|%s"  $svc) $n.Node true -}}
            {{- /* falt key -- for fast check "if the agent X is a live in service Y" */ -}}
            {{- scratch.Set (printf "aliveK|%s|%s" $svc $n.Node) true -}}
        {{- end -}}
        {{- end -}}
    {{- end -}}
    {{- $totalCnt := len (scratch.MapValues (printf "total|%s" $svc)) -}}
    {{- $aliveCnt := len (scratch.MapValues (printf "alive|%s" $svc)) -}}

    {{- /* 2. No monitoring agents are currently alive -> skip emitting this service block entirely.
            The DNS updater won't receive state data for this service -> the existing DNS A-record remains untouched. */ -}}
    {{- if gt $aliveCnt 0 -}}

        {{- /* 3. Build IP-to-count metrics and compile target unique IPs into a separate map context. */ -}}
        {{- range $p := $all -}}
        {{- if scratch.Key (printf "aliveK|%s|%s" $svc $p.Node) -}}
            
            {{- $hasCritical := false -}}
            {{- range $c := $p.Checks -}}
                {{- if eq $c.Status "critical" -}}
                    {{- $hasCritical = true -}}
                {{- end -}}
            {{- end -}}

            {{- if not $hasCritical -}}
                {{- $ck   := printf "cnt|%s|%s" $svc $p.Address -}}
                {{- $prev := 0 -}}
                {{- if scratch.Key $ck }}{{ $prev = scratch.Get $ck }}{{ end -}}
                {{- scratch.Set $ck (add $prev 1) -}}
                {{- scratch.MapSet (printf "ips|%s" $svc) $p.Address $p.Address -}}
            {{- end -}}

        {{- end -}}
        {{- end -}}

        {{- $ips := scratch.MapValues (printf "ips|%s" $svc) -}}
        {{- $status := "all_critical" -}}
        {{- if gt (len $ips) 0 }}{{ $status = "ok" }}{{ end -}}

        {{- $meta := (index $all 0).ServiceMeta -}}

        {{- if eq (index $meta "dns_provider") $DNS_PROVIDER_NAME -}}

            {{- if not $firstBlock }},{{ end }}
            {
                "service_name":   "{{ $svc }}",
                "record":         "{{ index $meta "record" }}",
                "zone":           "{{ index $meta "zone" }}",
                "dns_provider":   "{{ index $meta "dns_provider"}}",
                "ttl":            "{{ index $meta "ttl" }}",
                "status":         "{{ $status }}",
                "on_all_fail":    "{{ or (index $meta "on_all_fail") "keep" }}",
                "fallback_ip":    "{{ index $meta "fallback_ip" }}",
                "quorum":         {{ or (index $meta "quorum") "1" }},

                {{- /* Provider-specific fields, generated dynamically from metadata */ -}}
                {{- range $k, $v := $meta }}
                    {{- if not (in $commonFields $k) }}
                "{{ $k }}":    "{{ $v }}",
                    {{- end }}
                {{- end }}
                "agents_total":   {{ $totalCnt }},
                "agents_alive":   {{ $aliveCnt }},
                "ips":            [{{- $first := true -}}
                                {{- range $ip := $ips -}}
                                    {{- if not $first }},{{ end -}}
                                    "{{ $ip }}"
                                    {{- $first = false -}}
                                {{- end -}}],
                "confirmations":  { {{- $first := true -}}
                                {{- range $ip := $ips -}}
                                    {{- if not $first }},{{ end -}}
                                    "{{ $ip }}": {{ scratch.Get (printf "cnt|%s|%s" $svc $ip) }}
                                    {{- $first = false -}}
                                {{- end -}} }
            }
            {{- $firstBlock = false -}}
        {{- end -}}
    {{- end -}}
    {{- end -}}
{{- end -}}
{{- end }}
]
