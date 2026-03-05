const SEVERITY_COLORS = {
    'High': '#ff5252',
    'Medium': '#ffa400',
    'Low': '#4fc3f7',
    'Info': '#78909c',
};

function renderSeverityPie(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    const labels = Object.keys(data);
    const values = Object.values(data);
    const colors = labels.map(l => SEVERITY_COLORS[l] || '#546e7a');

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderWidth: 0,
                hoverBorderColor: '#fff',
                hoverBorderWidth: 2,
                spacing: 3,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            cutout: '72%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#90a4ae',
                        font: { family: 'Quicksand', weight: '600' },
                        usePointStyle: true,
                        pointStyleWidth: 10,
                        padding: 16,
                    }
                },
            }
        }
    });
}

function renderTopVulnsBar(canvasId, vulns) {
    const ctx = document.getElementById(canvasId);
    if (!ctx || !vulns.length) return;

    const bgColors = vulns.map(v => {
        const base = SEVERITY_COLORS[v.severity] || '#546e7a';
        return base + '99'; // semi-transparent
    });

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: vulns.map(v => v.name),
            datasets: [{
                label: 'CVSS Score',
                data: vulns.map(v => v.cvss_score),
                backgroundColor: bgColors,
                borderColor: vulns.map(v => SEVERITY_COLORS[v.severity] || '#546e7a'),
                borderWidth: 1,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            scales: {
                x: {
                    min: 0, max: 10,
                    title: { display: true, text: 'CVSS Score', color: '#90a4ae', font: { family: 'Quicksand' } },
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#90a4ae' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#bbdefb', font: { size: 11, family: 'Sarabun' } }
                }
            },
            plugins: {
                legend: { display: false },
            }
        }
    });
}
