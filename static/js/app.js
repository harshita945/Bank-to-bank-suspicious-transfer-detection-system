/**
 * Bank-to-Bank Suspicious Transaction Detection System
 * Frontend Interactions & Chart.js Visualizations
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Auto-dismiss Bootstrap alert notifications after 5 seconds
    const alerts = document.querySelectorAll(".alert-dismissible");
    alerts.forEach((alert) => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });

    // 2. Sender Account Selection on Transfer Page (Update Available Balance live)
    const senderSelect = document.getElementById("senderAccountSelect");
    const balanceDisplay = document.getElementById("availableBalanceDisplay");

    if (senderSelect && balanceDisplay) {
        function updateBalance() {
            const selectedOpt = senderSelect.options[senderSelect.selectedIndex];
            if (selectedOpt && selectedOpt.dataset.balance) {
                const bal = parseFloat(selectedOpt.dataset.balance);
                balanceDisplay.textContent = `Available Balance: INR ${bal.toLocaleString("en-IN", { minimumFractionDigits: 2 })}`;
                balanceDisplay.className = bal > 0 ? "text-success fw-semibold small" : "text-danger fw-semibold small";
            } else {
                balanceDisplay.textContent = "";
            }
        }
        senderSelect.addEventListener("change", updateBalance);
        updateBalance();
    }

    // 3. Load & Render Dashboard Charts if chart canvases are present
    const riskCanvas = document.getElementById("riskDistributionChart");
    const trendsCanvas = document.getElementById("dailyTrendsChart");
    const banksCanvas = document.getElementById("bankVolumeChart");

    if (riskCanvas || trendsCanvas || banksCanvas) {
        fetchChartsData();
    }
});

/**
 * Fetch dynamic analytics data from Flask API and render Chart.js charts
 */
async function fetchChartsData() {
    try {
        const response = await fetch("/api/chart-data");
        if (!response.ok) return;

        const data = await response.json();
        if (data.status !== "success") return;

        // 1. Risk Distribution Donut Chart
        const riskCanvas = document.getElementById("riskDistributionChart");
        if (riskCanvas) {
            const riskData = data.risk_distribution;
            new Chart(riskCanvas, {
                type: "doughnut",
                data: {
                    labels: ["Low Risk (0-29)", "Medium Risk (30-59)", "High Risk (60-100)"],
                    datasets: [{
                        data: [riskData.LOW || 0, riskData.MEDIUM || 0, riskData.HIGH || 0],
                        backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
                        borderWidth: 2,
                        borderColor: "#ffffff"
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: "bottom", labels: { boxWidth: 14, font: { size: 12 } } },
                        tooltip: {
                            callbacks: {
                                label: (ctx) => ` ${ctx.label}: ${ctx.raw} transactions`
                            }
                        }
                    },
                    cutout: "68%"
                }
            });
        }

        // 2. 7-Day Activity Trends Line Chart
        const trendsCanvas = document.getElementById("dailyTrendsChart");
        if (trendsCanvas) {
            const labels = data.daily_trends.map(t => t.date);
            const totals = data.daily_trends.map(t => t.total);
            const flagged = data.daily_trends.map(t => t.flagged);

            new Chart(trendsCanvas, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: "Total Transactions",
                            data: totals,
                            borderColor: "#0284c7",
                            backgroundColor: "rgba(2, 132, 199, 0.1)",
                            tension: 0.35,
                            fill: true,
                            pointRadius: 4
                        },
                        {
                            label: "Flagged Suspicious",
                            data: flagged,
                            borderColor: "#ef4444",
                            backgroundColor: "rgba(239, 68, 68, 0.1)",
                            tension: 0.35,
                            fill: true,
                            pointRadius: 4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { precision: 0 }
                        }
                    },
                    plugins: {
                        legend: { position: "top" }
                    }
                }
            });
        }

        // 3. Bank-wise Transaction Volume Bar Chart (if present on reports)
        const banksCanvas = document.getElementById("bankVolumeChart");
        if (banksCanvas && data.banks_data) {
            const bankLabels = data.banks_data.map(b => b.bank);
            const bankCounts = data.banks_data.map(b => b.count);

            new Chart(banksCanvas, {
                type: "bar",
                data: {
                    labels: bankLabels,
                    datasets: [{
                        label: "Transactions Count",
                        data: bankCounts,
                        backgroundColor: "#38bdf8",
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, ticks: { precision: 0 } }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

    } catch (err) {
        console.error("Error loading chart analytics:", err);
    }
}
