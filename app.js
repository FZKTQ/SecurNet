// SecurNet SOC Console — логика мониторинга, корреляции и реагирования SOAR

const state = {
  blockedIps: 14,
  epsHistory: [16800, 17400, 17900, 18250, 18600, 18100, 18450, 18900, 18300, 18520, 18420, 18680],
  anomalyHistory: [2, 3, 2, 4, 3, 2, 5, 3, 2, 3, 4, 3],
  incidents: [
    {
      id: "INC-2026-104",
      time: "08:02:14",
      type: "Brute-force SSH / Подбор паролей",
      rule: "SIEM-SSH-014",
      srcIp: "185.220.101.47",
      target: "srv-gateway-01",
      severity: "critical",
      status: "open",
      details: "Зафиксировано 142 неудачные попытки входа по протоколу SSH за 60 секунд. Рекомендуется блокировка IP на периметровом межсетевом экране."
    },
    {
      id: "INC-2026-103",
      time: "07:54:09",
      type: "Аномальная выгрузка данных (UEBA)",
      rule: "ML-UEBA-009",
      srcIp: "10.14.22.108",
      target: "db-clickhouse-02",
      severity: "critical",
      status: "open",
      details: "Нетипичный объем исходящего трафика (4.8 ГБ вне рабочего окна) от учетной записи svc_analytics. Отклонение от поведенческого профиля: 94%."
    },
    {
      id: "INC-2026-102",
      time: "07:41:51",
      type: "Попытка SQL-инъекции (OWASP A03)",
      rule: "WAF-SQLI-021",
      srcIp: "91.134.188.19",
      target: "api-gateway-prod",
      severity: "high",
      status: "mitigated",
      details: "Обнаружена сигнатура UNION SELECT в параметре запроса /api/v1/reports. IP автоматически добавлен в черный список SOAR."
    },
    {
      id: "INC-2026-101",
      time: "07:28:33",
      type: "Сканирование портов внутренней сети",
      rule: "IDS-SCAN-004",
      srcIp: "10.14.5.73",
      target: "subnet-10.14.0.0/24",
      severity: "medium",
      status: "open",
      details: "Сетевой сенсор NetFlow выявил последовательный опрос 1024 TCP-портов с рабочей станции отдела разработки."
    },
    {
      id: "INC-2026-100",
      time: "07:10:18",
      type: "Изменение политики доступа RBAC",
      rule: "AUDIT-RBAC-002",
      srcIp: "10.14.1.15",
      target: "securnet-iam",
      severity: "low",
      status: "closed",
      details: "Плановое предоставление прав аналитика L1 новому сотруднику SOC по заявке SD-4821."
    }
  ],
  cves: [
    {
      id: "CVE-2025-3142",
      component: "python-cryptography 41.0.1 (worker-02)",
      cvss: "8.1 (Высокий)",
      desc: "Уязвимость обработки X.509 сертификатов при проверке цепочки доверия.",
      status: "open"
    },
    {
      id: "CVE-2025-2790",
      component: "OpenSSL 3.0.12 (srv-gateway-01)",
      cvss: "7.5 (Высокий)",
      desc: "Потенциальный отказ в обслуживании (DoS) при разборе некорректных TLS-пакетов.",
      status: "open"
    },
    {
      id: "CVE-2024-5018",
      component: "nginx 1.24.0 (api-gateway-prod)",
      cvss: "5.3 (Средний)",
      desc: "Раскрытие версии сервера в служебных заголовках при нестандартных запросах.",
      status: "patched"
    }
  ]
};

const severityLabels = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий"
};

const statusLabels = {
  open: "Открыт",
  mitigated: "Заблокирован (SOAR)",
  closed: "Закрыт"
};

function getCurrentTimeStr() {
  return new Date().toTimeString().slice(0, 8);
}

function addAuditLog(message, level = "info") {
  const list = document.getElementById("auditLog");
  const li = document.createElement("li");
  if (level !== "info") li.classList.add(`log-${level}`);
  li.innerHTML = `<span class="log-time">[${getCurrentTimeStr()}]</span>${message}`;
  list.prepend(li);
  while (list.children.length > 20) {
    list.removeChild(list.lastChild);
  }
}

function updateKpis() {
  const openIncidents = state.incidents.filter((i) => i.status === "open");
  const openCritical = openIncidents.filter((i) => i.severity === "critical").length;

  document.getElementById("kpiActiveIncidents").textContent = openIncidents.length;
  document.getElementById("kpiBlockedIps").textContent = state.blockedIps;

  const badge = document.getElementById("kpiCritBadge");
  badge.textContent = `${openCritical} критич.`;
  badge.className = `kpi-tag ${openCritical > 0 ? "tag-warn" : "tag-ok"}`;
}

function renderIncidents() {
  const search = document.getElementById("searchInput").value.trim().toLowerCase();
  const sev = document.getElementById("severityFilter").value;
  const st = document.getElementById("statusFilter").value;

  const filtered = state.incidents.filter((item) => {
    const matchText =
      item.id.toLowerCase().includes(search) ||
      item.type.toLowerCase().includes(search) ||
      item.srcIp.toLowerCase().includes(search) ||
      item.target.toLowerCase().includes(search);
    const matchSev = sev === "all" || item.severity === sev;
    const matchStatus = st === "all" || item.status === st;
    return matchText && matchSev && matchStatus;
  });

  const tbody = document.getElementById("incidentsBody");
  tbody.innerHTML = "";

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:24px;">Инциденты по заданным фильтрам не найдены</td></tr>`;
    return;
  }

  filtered.forEach((inc) => {
    const tr = document.createElement("tr");

    let actionBtns = `<button class="btn btn-secondary btn-sm" data-action="view" data-id="${inc.id}">Детали</button>`;
    if (inc.status === "open") {
      actionBtns += `<button class="btn btn-danger btn-sm" data-action="block" data-id="${inc.id}">Блок IP</button>`;
      actionBtns += `<button class="btn btn-primary btn-sm" data-action="close" data-id="${inc.id}">Закрыть</button>`;
    } else if (inc.status === "mitigated") {
      actionBtns += `<button class="btn btn-secondary btn-sm" data-action="rollback" data-id="${inc.id}">Откат</button>`;
      actionBtns += `<button class="btn btn-primary btn-sm" data-action="close" data-id="${inc.id}">Закрыть</button>`;
    }

    tr.innerHTML = `
      <td class="mono">${inc.id}</td>
      <td class="mono">${inc.time}</td>
      <td><strong>${inc.type}</strong><br><span class="mono" style="color:#94a3b8;font-size:0.75rem;">${inc.rule}</span></td>
      <td class="mono">${inc.srcIp}</td>
      <td class="mono">${inc.target}</td>
      <td><span class="sev-badge sev-${inc.severity}">${severityLabels[inc.severity]}</span></td>
      <td><span class="status-badge st-${inc.status}">${statusLabels[inc.status]}</span></td>
      <td><div class="action-group">${actionBtns}</div></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderCves() {
  const tbody = document.getElementById("cveBody");
  tbody.innerHTML = "";

  state.cves.forEach((cve) => {
    const isPatched = cve.status === "patched";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono"><strong>${cve.id}</strong></td>
      <td class="mono">${cve.component}</td>
      <td>${cve.cvss}</td>
      <td>${cve.desc}</td>
      <td><span class="status-badge ${isPatched ? "st-closed" : "st-open"}">${isPatched ? "Устранена" : "Активна"}</span></td>
      <td>
        ${
          isPatched
            ? `<span style="color:#86efac;font-size:0.8rem;">Патч применен</span>`
            : `<button class="btn btn-primary btn-sm" data-cve="${cve.id}">Применить патч</button>`
        }
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function handleIncidentAction(action, id) {
  const inc = state.incidents.find((x) => x.id === id);
  if (!inc) return;

  if (action === "view") {
    openIncidentModal(inc);
    return;
  }

  if (action === "block") {
    inc.status = "mitigated";
    state.blockedIps += 1;
    addAuditLog(`SOAR: IP <strong>${inc.srcIp}</strong> заблокирован на межсетевом экране (${inc.id})`, "ok");
  } else if (action === "rollback") {
    inc.status = "open";
    state.blockedIps = Math.max(0, state.blockedIps - 1);
    addAuditLog(`SOAR Rollback: снята блокировка с IP <strong>${inc.srcIp}</strong> (${inc.id})`, "warn");
  } else if (action === "close") {
    inc.status = "closed";
    addAuditLog(`Оператор SOC закрыл инцидент <strong>${inc.id}</strong>`, "ok");
  }

  updateKpis();
  renderIncidents();
}

function openIncidentModal(inc) {
  document.getElementById("modalTitle").textContent = `Карточка инцидента ${inc.id}`;
  document.getElementById("modalBody").innerHTML = `
    <div class="detail-row"><span>Тип угрозы:</span><strong>${inc.type}</strong></div>
    <div class="detail-row"><span>Правило корреляции:</span><strong class="mono">${inc.rule}</strong></div>
    <div class="detail-row"><span>Источник (IP):</span><strong class="mono">${inc.srcIp}</strong></div>
    <div class="detail-row"><span>Целевой узел:</span><strong class="mono">${inc.target}</strong></div>
    <div class="detail-row"><span>Критичность:</span><strong>${severityLabels[inc.severity]}</strong></div>
    <div class="detail-row"><span>Статус:</span><strong>${statusLabels[inc.status]}</strong></div>
    <p style="margin-top:6px;color:#cbd5e1;">${inc.details}</p>
  `;

  const footer = document.getElementById("modalFooter");
  footer.innerHTML = `<button class="btn btn-secondary" type="button" id="modalOkBtn">Закрыть окно</button>`;
  document.getElementById("modalOkBtn").onclick = closeModal;

  document.getElementById("incidentModal").classList.add("open");
}

function closeModal() {
  document.getElementById("incidentModal").classList.remove("open");
}

function simulateAttack() {
  const templates = [
    {
      type: "DDoS SYN-Flood на внешний периметр",
      rule: "DPI-DDOS-019",
      srcIp: `45.155.205.${Math.floor(20 + Math.random() * 210)}`,
      target: "edge-router-01",
      severity: "critical",
      details: "Резкий всплеск полуоткрытых TCP-соединений (более 12 000 SYN/сек). Требуется активация SOAR-плейбука фильтрации."
    },
    {
      type: "Подозрительный запуск PowerShell (EDR)",
      rule: "EDR-PS-033",
      srcIp: `10.14.8.${Math.floor(10 + Math.random() * 190)}`,
      target: "ws-finance-14",
      severity: "high",
      details: "Агент конечной точки зафиксировал выполнение обфусцированной команды PowerShell с параметром -EncodedCommand."
    }
  ];

  const tpl = templates[Math.floor(Math.random() * templates.length)];
  const nextNum = 105 + state.incidents.length;
  const newIncident = {
    id: `INC-2026-${nextNum}`,
    time: getCurrentTimeStr(),
    ...tpl,
    status: "open"
  };

  state.incidents.unshift(newIncident);
  state.epsHistory.push(19600 + Math.floor(Math.random() * 900));
  state.epsHistory.shift();
  state.anomalyHistory.push(11 + Math.floor(Math.random() * 5));
  state.anomalyHistory.shift();

  addAuditLog(`ТРЕВОГА: выявлена угроза <strong>${newIncident.type}</strong> (${newIncident.srcIp})`, "danger");
  updateKpis();
  renderIncidents();
  drawChart();
}

function exportJsonReport() {
  const payload = {
    system: "SecurNet v1.2.0",
    exportedAt: new Date().toISOString(),
    metrics: {
      currentEps: state.epsHistory[state.epsHistory.length - 1],
      blockedIps: state.blockedIps,
      activeIncidents: state.incidents.filter((i) => i.status === "open").length
    },
    incidents: state.incidents,
    vulnerabilities: state.cves
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `securnet-report-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  addAuditLog("Выгружен отчет по инцидентам в формате JSON (аудит RBAC)", "info");
}

function drawChart() {
  const canvas = document.getElementById("telemetryChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const padL = 52;
  const padR = 16;
  const padT = 18;
  const padB = 28;
  const chartW = w - padL - padR;
  const chartH = h - padT - padB;

  // Grid lines
  ctx.strokeStyle = "#24324a";
  ctx.lineWidth = 1;
  ctx.font = "11px monospace";
  ctx.fillStyle = "#94a3b8";

  const minEps = 15000;
  const maxEps = 21000;
  for (let i = 0; i <= 4; i++) {
    const y = padT + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(w - padR, y);
    ctx.stroke();

    const val = Math.round(maxEps - ((maxEps - minEps) / 4) * i);
    ctx.fillText(val.toString(), 6, y + 4);
  }

  const pts = state.epsHistory.length;
  const stepX = chartW / (pts - 1);

  // EPS Area + Line
  ctx.beginPath();
  state.epsHistory.forEach((v, idx) => {
    const x = padL + idx * stepX;
    const norm = Math.max(0, Math.min(1, (v - minEps) / (maxEps - minEps)));
    const y = padT + chartH - norm * chartH;
    if (idx === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });

  ctx.strokeStyle = "#38bdf8";
  ctx.lineWidth = 2.5;
  ctx.stroke();

  ctx.lineTo(padL + (pts - 1) * stepX, padT + chartH);
  ctx.lineTo(padL, padT + chartH);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, padT, 0, padT + chartH);
  grad.addColorStop(0, "rgba(56, 189, 248, 0.28)");
  grad.addColorStop(1, "rgba(56, 189, 248, 0.0)");
  ctx.fillStyle = grad;
  ctx.fill();

  // Anomaly Bars
  state.anomalyHistory.forEach((a, idx) => {
    const x = padL + idx * stepX;
    const barH = Math.min(chartH, (a / 18) * chartH);
    ctx.fillStyle = a >= 8 ? "rgba(239, 68, 68, 0.85)" : "rgba(239, 68, 68, 0.45)";
    ctx.fillRect(x - 5, padT + chartH - barH, 10, barH);
  });

  // X labels
  ctx.fillStyle = "#94a3b8";
  for (let idx = 0; idx < pts; idx += 2) {
    const x = padL + idx * stepX;
    ctx.fillText(`-${(pts - 1 - idx) * 5}с`, x - 12, h - 8);
  }
}

function tickTelemetry() {
  const nextEps = 17800 + Math.floor(Math.random() * 1450);
  const nextAnom = Math.random() > 0.82 ? 5 + Math.floor(Math.random() * 4) : 1 + Math.floor(Math.random() * 3);
  state.epsHistory.push(nextEps);
  state.epsHistory.shift();
  state.anomalyHistory.push(nextAnom);
  state.anomalyHistory.shift();

  document.getElementById("kpiEps").textContent = nextEps.toLocaleString("ru-RU");
  document.getElementById("kpiLatency").textContent = `${(1.18 + Math.random() * 0.34).toFixed(2)} с`;
  drawChart();
}

// Инициализация интерфейса и обработчиков событий
document.addEventListener("DOMContentLoaded", () => {
  // Вкладки
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });

  // Фильтры
  document.getElementById("searchInput").addEventListener("input", renderIncidents);
  document.getElementById("severityFilter").addEventListener("change", renderIncidents);
  document.getElementById("statusFilter").addEventListener("change", renderIncidents);

  // Действия в таблице инцидентов
  document.getElementById("incidentsBody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (btn) handleIncidentAction(btn.dataset.action, btn.dataset.id);
  });

  // Действия в таблице CVE
  document.getElementById("cveBody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-cve]");
    if (!btn) return;
    const item = state.cves.find((c) => c.id === btn.dataset.cve);
    if (item) {
      item.status = "patched";
      addAuditLog(`SCA/DevSecOps: применен патч безопасности для <strong>${item.id}</strong>`, "ok");
      renderCves();
    }
  });

  document.getElementById("btnRescanCve").addEventListener("click", () => {
    addAuditLog("Запущено внеплановое сканирование уязвимостей (Trivy / CVE-аудит)", "info");
  });

  document.getElementById("btnSimulateAttack").addEventListener("click", simulateAttack);
  document.getElementById("btnExportReport").addEventListener("click", exportJsonReport);
  document.getElementById("btnClearLog").addEventListener("click", () => {
    document.getElementById("auditLog").innerHTML = "";
  });

  // Модальное окно
  document.getElementById("btnCloseModal").addEventListener("click", closeModal);
  document.getElementById("incidentModal").addEventListener("click", (e) => {
    if (e.target.id === "incidentModal") closeModal();
  });

  // Первичный рендер
  updateKpis();
  renderIncidents();
  renderCves();
  drawChart();
  addAuditLog("Веб-консоль ИС «SecurNet» инициализирована. Шина Kafka подключена.", "ok");
  addAuditLog("Загружен актуальный набор правил корреляции ruleset-v1.2.4", "info");

  setInterval(tickTelemetry, 3500);
});
