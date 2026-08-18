{{- $DNS_PROVIDER_NAME := mustEnv "DNS_PROVIDER_NAME" -}}
{{- $SERVICE_NAME_REGEX := mustEnv "SERVICE_NAME_REGEX" -}}
{{- $COMBINED_REGEX := printf "%s%s" $SERVICE_NAME_REGEX $DNS_PROVIDER_NAME -}}

{{- $commonFields := sprig_list
    "check_target"
    "config_hash"
    "dns_provider"
    "fallback_ip"
    "minimum_observers"
    "on_all_fail"
    "owner_site"
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

        {{- /* Один site даёт не более одного голоса, если в site несколько одноимённых агентов. */ -}}
        {{- range $instance := $all -}}
            {{- $ip := $instance.Address -}}
            {{- $site := index $instance.ServiceMeta "site" -}}
            {{- scratch.MapSet (printf "candidate|%s" $svc) $ip $ip -}}

            {{- $nodeLive := false -}}
            {{- $checkPassing := false -}}
            {{- $checkObserved := false -}}
            {{- range $check := $instance.Checks -}}
                {{- if and (eq $check.CheckID "serfHealth") (eq $check.Status "passing") -}}
                    {{- $nodeLive = true -}}
                {{- end -}}
                {{- if and (ne $check.CheckID "serfHealth") (eq $check.Status "passing") -}}
                    {{- $checkPassing = true -}}
                    {{- $checkObserved = true -}}
                {{- end -}}
                {{- if and (ne $check.CheckID "serfHealth") (eq $check.Status "critical") -}}
                    {{- $checkObserved = true -}}
                {{- end -}}
            {{- end -}}

            {{- /* warning = ошибка проверки и не является ответом статуса цели. */ -}}
            {{- if and $nodeLive $checkObserved -}}
                {{- scratch.MapSet (printf "observed|%s|%s" $svc $ip) $site true -}}
                {{- if $checkPassing -}}
                    {{- scratch.MapSet (printf "passing|%s|%s" $svc $ip) $site true -}}
                {{- end -}}
            {{- end -}}
        {{- end -}}

        {{- $meta := (index $all 0).ServiceMeta -}}
        {{- if eq (index $meta "dns_provider") $DNS_PROVIDER_NAME -}}
            {{- if not $firstBlock }},{{ end }}
            {
                "service_name": "{{ $svc }}",
                "record": "{{ index $meta "record" }}",
                "zone": "{{ index $meta "zone" }}",
                "dns_provider": "{{ index $meta "dns_provider" }}",
                "owner_site": "{{ index $meta "owner_site" }}",
                "ttl": "{{ index $meta "ttl" }}",
                "on_all_fail": "{{ or (index $meta "on_all_fail") "keep" }}",
                "fallback_ip": "{{ index $meta "fallback_ip" }}",
                "quorum": {{ or (index $meta "quorum") "1" }},
                "minimum_observers": {{ or (index $meta "minimum_observers") (or (index $meta "quorum") "1") }},
                {{- range $k, $v := $meta }}
                    {{- if not (in $commonFields $k) }}
                "{{ $k }}": "{{ $v }}",
                    {{- end }}
                {{- end }}
                "candidates": [
                    {{- $first := true -}}
                    {{- range $ip := scratch.MapValues (printf "candidate|%s" $svc) -}}
                        {{- if not $first }},{{ end }}"{{ $ip }}"
                        {{- $first = false -}}
                    {{- end -}}
                ],

                {{- /* Сколько живых site дали результат */ -}}
                "observations": {
                    {{- $first := true -}}
                    {{- range $ip := scratch.MapValues (printf "candidate|%s" $svc) -}}
                        {{- if not $first }},{{ end }}
                        "{{ $ip }}": {{ len (scratch.MapValues (printf "observed|%s|%s" $svc $ip)) }}
                        {{- $first = false -}}
                    {{- end -}}
                },

                {{- /* сколько разных site подтвердили доступность */ -}}
                "confirmations": {
                    {{- $first := true -}}
                    {{- range $ip := scratch.MapValues (printf "candidate|%s" $svc) -}}
                        {{- if not $first }},{{ end }}
                        "{{ $ip }}": {{ len (scratch.MapValues (printf "passing|%s|%s" $svc $ip)) }}
                        {{- $first = false -}}
                    {{- end -}}
                }
            }
            {{- $firstBlock = false -}}
        {{- end -}}
    {{- end -}}
{{- end -}}
{{- end }}
]
