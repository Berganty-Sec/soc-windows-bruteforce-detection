#!/usr/bin/env python3
"""Detecta padrões compatíveis com força bruta em eventos 4625 do Windows."""

from __future__ import annotations

import argparse
import locale
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
FAILED_LOGON_ID = "4625"
FAILED_AUTH_EVENT_IDS = {"4625", "4771", "4776", "4777"}
EVENT_TITLES = {
    "4625": "Falha de logon",
    "4771": "Falha de pré-autenticação Kerberos",
    "4776": "Validação de credenciais NTLM",
    "4777": "Falha na validação de credenciais NTLM",
}
LOGON_TYPES = {
    "0": ("System", "Local / sistema"),
    "2": ("Interactive", "Local (console/teclado)"),
    "3": ("Network", "Via rede"),
    "4": ("Batch", "Local (tarefa em lote)"),
    "5": ("Service", "Local (serviço)"),
    "7": ("Unlock", "Local (desbloqueio)"),
    "8": ("NetworkCleartext", "Via rede (credenciais enviadas ao serviço)"),
    "9": ("NewCredentials", "Credenciais para conexão de rede"),
    "10": ("RemoteInteractive", "Remoto (Área de Trabalho Remota/RDP)"),
    "11": ("CachedInteractive", "Local (credenciais em cache)"),
    "12": ("CachedRemoteInteractive", "Remoto (credenciais em cache)"),
    "13": ("CachedUnlock", "Local (desbloqueio com credenciais em cache)"),
}
FAILURE_CODES = {
    "0xc0000064": "A conta de usuário não existe.",
    "0xc000006a": "A senha informada está incorreta.",
    "0xc000006d": "Usuário ou senha inválidos.",
    "0xc000006e": "Restrição na conta impediu a autenticação.",
    "0xc000006f": "Tentativa fora do horário permitido para a conta.",
    "0xc0000070": "Estação de trabalho não permitida para esta conta.",
    "0xc0000071": "A senha da conta expirou.",
    "0xc0000072": "A conta está desativada.",
    "0xc0000133": "Diferença de horário entre cliente e servidor.",
    "0xc000015b": "A conta não tem permissão para este tipo de logon.",
    "0xc0000193": "A conta expirou.",
    "0xc0000224": "A conta precisa trocar a senha.",
    "0xc0000234": "A conta está bloqueada.",
    "0xc0000380": "PIN incorreto no fluxo de autenticação por cartão inteligente.",
    "0x6": "A conta não foi encontrada no domínio (Kerberos).",
    "0x12": "A conta está revogada ou desativada (Kerberos).",
    "0x17": "A senha expirou (Kerberos).",
    "0x18": "A senha está incorreta (pré-autenticação Kerberos).",
    "%%2304": "O Windows registrou um erro durante o logon; consulte Status/SubStatus para o detalhe.",
}


@dataclass(frozen=True)
class FailedLogon:
    timestamp: datetime
    username: str
    source_ip: str
    workstation: str
    logon_type: str
    status: str
    sub_status: str
    failure_reason: str = "-"
    target_domain: str = "-"
    ip_port: str = "-"
    authentication_package: str = "-"
    logon_process: str = "-"
    process_name: str = "-"
    subject_username: str = "-"
    subject_domain: str = "-"
    subject_logon_id: str = "-"
    target_logon_id: str = "-"
    transmitted_services: str = "-"
    key_length: str = "-"
    record_id: str = "-"
    event_id: str = FAILED_LOGON_ID
    event_title: str = EVENT_TITLES[FAILED_LOGON_ID]


def _event_from_xml(xml_text: str) -> FailedLogon | None:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    event_id = root.findtext("e:System/e:EventID", namespaces=EVENT_NS)
    if event_id not in FAILED_AUTH_EVENT_IDS:
        return None
    time_node = root.find("e:System/e:TimeCreated", EVENT_NS)
    if time_node is None or not time_node.get("SystemTime"):
        return None
    try:
        timestamp = datetime.fromisoformat(time_node.get("SystemTime").replace("Z", "+00:00"))
    except ValueError:
        return None
    fields = {
        node.get("Name", ""): node.text or ""
        for node in root.findall("e:EventData/e:Data", EVENT_NS)
    }
    def field(*names: str, default: str = "-") -> str:
        for name in names:
            value = fields.get(name)
            if value not in (None, ""):
                return value
        return default

    status = field("Status", "ErrorCode", "FailureCode")
    # O evento 4776 registra validações NTLM bem-sucedidas e malsucedidas;
    # Status zero indica sucesso e não deve entrar no relatório de falhas.
    if event_id == "4776" and status.lower() in ("0x0", "0x00000000", "0"):
        return None
    record_id = root.findtext("e:System/e:EventRecordID", default="-", namespaces=EVENT_NS)
    logon_type = field("LogonType")
    if logon_type == "-" and event_id != FAILED_LOGON_ID:
        logon_type = EVENT_TITLES[event_id]
    username = field("TargetUserName", "AccountName", "UserName", default="(desconhecido)")
    if username in ("", "-", "(desconhecido)"):
        username = "(não informado pelo Windows)"
    return FailedLogon(
        timestamp=timestamp,
        username=username,
        source_ip=field("IpAddress", "ClientAddress"),
        workstation=field("WorkstationName", "Workstation", "ClientName"),
        logon_type=logon_type,
        status=status,
        sub_status=field("SubStatus"),
        failure_reason=field("FailureReason", "ErrorCode", "FailureCode"),
        target_domain=field("TargetDomainName", "TargetDomain"),
        ip_port=field("IpPort", "ClientPort"),
        authentication_package=field("AuthenticationPackageName", "PackageName"),
        logon_process=field("LogonProcessName"),
        process_name=field("ProcessName"),
        subject_username=field("SubjectUserName"),
        subject_domain=field("SubjectDomainName"),
        subject_logon_id=field("SubjectLogonId"),
        target_logon_id=field("TargetLogonId"),
        transmitted_services=field("TransmittedServices"),
        key_length=field("KeyLength"),
        record_id=record_id or "-",
        event_id=event_id,
        event_title=EVENT_TITLES[event_id],
    )


def _query_wevtutil(source: str, xpath: str, max_events: int, is_file: bool) -> Iterable[FailedLogon]:
    command = ["wevtutil.exe", "qe", source]
    if is_file:
        command.append("/lf:true")
    command.extend([f"/q:{xpath}", "/f:xml", f"/c:{max_events}", "/rd:true"])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            timeout=120,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("O comando wevtutil.exe não foi encontrado no sistema.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("A consulta ao log de eventos excedeu 120 segundos.") from exc
    if result.returncode:
        detail = result.stderr.strip() or "wevtutil não conseguiu consultar a origem."
        raise RuntimeError(f"Falha na consulta ao log de eventos: {detail}")
    content = result.stdout.strip()
    if not content:
        return
    # wevtutil emite um elemento <Event> por registro, sem elemento raiz.
    try:
        root = ET.fromstring(f"<Events>{content}</Events>")
    except ET.ParseError as exc:
        raise RuntimeError(f"Não foi possível interpretar o XML do EVTX: {exc}") from exc
    for node in root.findall("e:Event", EVENT_NS):
        event = _event_from_xml(ET.tostring(node, encoding="unicode"))
        if event:
            yield event


def _read_evtx_with_wevtutil(path: Path, max_events: int) -> Iterable[FailedLogon]:
    event_filter = " or ".join(f"EventID={event_id}" for event_id in sorted(FAILED_AUTH_EVENT_IDS))
    xpath = f"*[System[({event_filter})]]"
    yield from _query_wevtutil(str(path), xpath, max_events, is_file=True)


def read_events(path: Path, max_events: int = 5000) -> Iterable[FailedLogon]:
    """Lê XML ou EVTX; no Windows, wevtutil permite ler EVTX sem pacote externo."""
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        try:
            from Evtx.Evtx import Evtx
        except ImportError:
            yield from _read_evtx_with_wevtutil(path, max_events)
            return
        with Evtx(str(path)) as log:
            count = 0
            for record in log.records():
                event = _event_from_xml(record.xml())
                if event:
                    yield event
                    count += 1
                    if count >= max_events:
                        break
        return

    # XML exportado pelo Visualizador de Eventos pode conter um <Events> ou
    # apenas um <Event>. O iterparse evita carregar todo o arquivo na memória.
    try:
        for _, element in ET.iterparse(path, events=("end",)):
            if element.tag.rsplit("}", 1)[-1] == "Event":
                event = _event_from_xml(ET.tostring(element, encoding="unicode"))
                if event:
                    yield event
                element.clear()
    except ET.ParseError as exc:
        raise RuntimeError(f"XML inválido: {exc}") from exc


def read_live_events(hours: int, max_events: int) -> list[FailedLogon]:
    """Consulta diretamente o log Segurança do Windows usando wevtutil."""
    if sys.platform != "win32":
        raise RuntimeError("A consulta automática ao log do Windows só funciona no Windows.")
    hours = max(1, hours)
    max_events = max(1, max_events)
    event_filter = " or ".join(f"EventID={event_id}" for event_id in sorted(FAILED_AUTH_EVENT_IDS))
    window_ms = hours * 60 * 60 * 1000
    xpath = f"*[System[({event_filter}) and TimeCreated[timediff(@SystemTime) <= {window_ms}]]]"
    try:
        return list(_query_wevtutil("Security", xpath, max_events, is_file=False))
    except RuntimeError as exc:
        raise RuntimeError(f"{exc} Verifique as permissões de leitura do log Segurança.") from exc


def _origin(event: FailedLogon) -> str:
    if event.source_ip in ("::1", "127.0.0.1"):
        return "localhost"
    if event.source_ip not in ("", "-"):
        return event.source_ip
    if event.workstation not in ("", "-"):
        return event.workstation
    return "(origem desconhecida)"


def _qualifying_windows(records: list[FailedLogon], window: timedelta, qualifies) -> list[list[FailedLogon]]:
    """Retorna uma amostra ao cruzar o limite, evitando um alerta por evento."""
    records.sort(key=lambda item: item.timestamp)
    active: deque[FailedLogon] = deque()
    alerted = False
    found = []
    for event in records:
        active.append(event)
        while active and event.timestamp - active[0].timestamp > window:
            active.popleft()
        if not qualifies(active):
            alerted = False
        elif not alerted:
            found.append(list(active))
            alerted = True
    return found


def find_bursts(events: Iterable[FailedLogon], threshold: int, window_minutes: int, spray_threshold: int):
    """Detecta repetição contra uma conta e pulverização contra várias contas."""
    window = timedelta(minutes=window_minutes)
    by_origin_user: dict[tuple[str, str], list[FailedLogon]] = defaultdict(list)
    by_origin: dict[str, list[FailedLogon]] = defaultdict(list)
    for event in events:
        origin = _origin(event)
        by_origin_user[(origin, event.username)].append(event)
        by_origin[origin].append(event)

    alerts = []
    for (origin, username), records in by_origin_user.items():
        for sample in _qualifying_windows(records, window, lambda active: len(active) >= threshold):
            alerts.append(("Força bruta contra uma conta", origin, username, sample))

    for origin, records in by_origin.items():
        for sample in _qualifying_windows(
            records, window, lambda active: len({event.username for event in active}) >= spray_threshold
        ):
            accounts = ", ".join(sorted({event.username for event in sample}))
            alerts.append(("Possível password spraying", origin, accounts, sample))
    return sorted(alerts, key=lambda alert: alert[3][-1].timestamp)


def _failure_description(event: FailedLogon) -> str:
    code = event.sub_status if event.sub_status not in ("", "-", "0x0", "0x00000000") else event.status
    description = FAILURE_CODES.get(code.lower()) or FAILURE_CODES.get(code)
    if description:
        return description
    if event.failure_reason not in ("", "-"):
        return FAILURE_CODES.get(event.failure_reason.lower()) or FAILURE_CODES.get(event.failure_reason) or event.failure_reason
    return "O Windows não forneceu uma descrição específica para este código."


def _logon_description(logon_type: str, event_id: str = FAILED_LOGON_ID) -> tuple[str, str]:
    if event_id == "4771":
        return "Kerberos", "Via rede (pré-autenticação Kerberos)"
    if event_id in ("4776", "4777"):
        return "NTLM", "Via rede (validação de credenciais NTLM)"
    return LOGON_TYPES.get(logon_type, ("Desconhecido", "Não classificado pelo tipo de logon"))


def _format_datetime(value: datetime) -> str:
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def build_report(events: list[FailedLogon], alerts, source_description: str,
                 threshold: int, spray_threshold: int, window_minutes: int) -> str:
    lines = [
        "RELATÓRIO DE FALHAS DE AUTENTICAÇÃO DO WINDOWS",
        f"Gerado em: {_format_datetime(datetime.now().astimezone())}",
        f"Origem analisada: {source_description}",
        f"Tentativas de autenticação malsucedidas: {len(events)}",
        f"Parâmetros: {threshold} falhas por conta; {spray_threshold} contas distintas; janela de {window_minutes} minutos.",
        "",
        "RESUMO DOS ALERTAS",
    ]
    if alerts:
        for number, (kind, origin, accounts, sample) in enumerate(alerts, 1):
            lines.extend([
                f"{number}. {kind}",
                f"   Origem: {origin}",
                f"   Conta(s): {accounts}",
                f"   Tentativas no intervalo: {len(sample)}",
                f"   Período: {_format_datetime(sample[0].timestamp)} a {_format_datetime(sample[-1].timestamp)}",
            ])
    else:
        lines.append("Nenhum padrão de força bruta atingiu os limites configurados.")

    lines.extend(["", "DETALHES DE CADA FALHA"])
    if not events:
        lines.append("Nenhum evento 4625 encontrado no período consultado.")
    for number, event in enumerate(sorted(events, key=lambda item: item.timestamp), 1):
        type_name, connection = _logon_description(event.logon_type, event.event_id)
        account = f"{event.target_domain}\\{event.username}" if event.target_domain not in ("", "-") else event.username
        origin_parts = [f"IP {event.source_ip}"] if event.source_ip not in ("", "-") else []
        if event.ip_port not in ("", "-"):
            origin_parts.append(f"porta {event.ip_port}")
        if event.workstation not in ("", "-"):
            origin_parts.append(f"estação {event.workstation}")
        origin = ", ".join(origin_parts) or "origem não informada"
        lines.extend([
            "",
            f"{number}. {event.event_title} em {_format_datetime(event.timestamp)} (evento {event.event_id}, registro {event.record_id})",
            f"   Usuário tentado: {account}",
            (f"   Tipo de logon: {event.logon_type} — {type_name}" if event.event_id == FAILED_LOGON_ID
             else f"   Tipo de autenticação: {type_name} (evento {event.event_id})"),
            f"   Caminho classificado: {connection}",
            f"   Origem: {origin}",
            f"   Tipo de falha: {_failure_description(event)}",
            f"   Status/SubStatus: {event.status} / {event.sub_status}",
            f"   Motivo informado pelo Windows: {_failure_description(event)}",
            f"   Pacote de autenticação: {event.authentication_package}",
            f"   Processo de logon: {event.logon_process}",
            f"   Processo relacionado: {event.process_name}",
            f"   Conta que solicitou o logon: {event.subject_domain}\\{event.subject_username}",
            f"   IDs de logon (solicitante/alvo): {event.subject_logon_id} / {event.target_logon_id}",
            f"   Serviços transmitidos: {event.transmitted_services}; tamanho da chave: {event.key_length}",
        ])
    lines.extend([
        "",
        "COMO LER A CLASSIFICAÇÃO",
        "No evento 4625, a classificação local/rede é inferida do campo LogonType: 2 normalmente indica tentativa no console; 3 indica autenticação via rede; 10 indica sessão remota/RDP. Kerberos (4771) e validações NTLM (4776/4777) são classificados como autenticação via rede; confira também o IP e a estação de origem.",
        "Os alertas indicam padrões compatíveis com força bruta ou password spraying; falhas legítimas e serviços mal configurados também podem gerar padrões semelhantes.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Registra tentativas malsucedidas de autenticação e gera um relatório detalhado. Sem arquivo, consulta o Windows diretamente.",
        epilog="Exemplos: python analisar_logins.py  |  python analisar_logins.py Security.evtx --limite 5 --janela 10",
    )
    parser.add_argument("arquivo", nargs="?", type=Path, help="Opcional: arquivo .evtx ou XML; sem arquivo, consulta o log Segurança diretamente")
    parser.add_argument("--limite", type=int, default=5, help="Falhas mínimas para gerar alerta (padrão: 5)")
    parser.add_argument("--janela", type=int, default=10, help="Janela de tempo em minutos (padrão: 10)")
    parser.add_argument("--contas-limite", type=int, default=5,
                        help="Contas distintas para sinalizar password spraying (padrão: 5)")
    parser.add_argument("--horas", type=int, default=24, help="No modo automático, consulta as últimas N horas (padrão: 24)")
    parser.add_argument("--max-eventos", type=int, default=5000, help="Máximo de eventos lidos no modo automático (padrão: 5000)")
    parser.add_argument("--relatorio", type=Path, help="Caminho do relatório .txt (padrão: nome gerado automaticamente)")
    args = parser.parse_args()
    if args.limite < 2 or args.janela < 1 or args.contas_limite < 2:
        parser.error("--limite e --contas-limite devem ser pelo menos 2; --janela deve ser positiva")
    if args.horas < 1 or args.max_eventos < 1:
        parser.error("--horas e --max-eventos devem ser positivos")
    try:
        if args.arquivo:
            if not args.arquivo.is_file():
                parser.error(f"arquivo não encontrado: {args.arquivo}")
            events = list(read_events(args.arquivo, args.max_eventos))
            source_description = str(args.arquivo.resolve())
        else:
            events = read_live_events(args.horas, args.max_eventos)
            source_description = f"log Segurança do Windows, últimas {args.horas} horas (máximo {args.max_eventos} eventos)"
    except (OSError, RuntimeError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    alerts = find_bursts(events, args.limite, args.janela, args.contas_limite)
    report = build_report(events, alerts, source_description, args.limite, args.contas_limite, args.janela)
    report_path = args.relatorio or Path.cwd() / f"relatorio_logins_{datetime.now().astimezone():%Y%m%d_%H%M%S}.txt"
    try:
        report_path.write_text(report, encoding="utf-8")
    except OSError as exc:
        print(f"Erro ao gravar relatório em {report_path}: {exc}", file=sys.stderr)
        return 2
    print(f"Tentativas malsucedidas encontradas: {len(events)}")
    print(f"Alertas de força bruta: {len(alerts)}")
    for number, event in enumerate(sorted(events, key=lambda item: item.timestamp), 1):
        _, connection = _logon_description(event.logon_type, event.event_id)
        print(f"  {number}. {_format_datetime(event.timestamp)} | usuário={event.username} | {event.event_title} | {connection}")
    print(f"Relatório detalhado salvo em: {report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
