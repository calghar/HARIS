(function() {
  var sevColors = {
    critical: '#f43f5e', high: '#f97316', medium: '#eab308',
    low: '#22c55e', info: '#06b6d4'
  };
  var trendChart = null;
  var doughnutChart = null;
  var trendsData = null;

  function getThemeColors() {
    var s = getComputedStyle(document.documentElement);
    return {
      text: s.getPropertyValue('--fg-muted').trim(),
      grid: s.getPropertyValue('--border').trim(),
      cardBg: s.getPropertyValue('--bg-card').trim()
    };
  }

  function renderCharts(data) {
    var tc = getThemeColors();

    // Line chart
    var trendEl = document.getElementById('findings-trend');
    if (trendEl && data.labels.length > 1) {
      if (trendChart) trendChart.destroy();
      var datasets = Object.entries(data.datasets)
        .filter(function(e) { return e[1].some(function(v) { return v > 0; }); })
        .map(function(e) {
          var sev = e[0], values = e[1];
          return {
            label: sev.charAt(0).toUpperCase() + sev.slice(1),
            data: values,
            borderColor: sevColors[sev],
            backgroundColor: sevColors[sev] + '15',
            tension: .35, pointRadius: 4, pointHoverRadius: 6,
            borderWidth: 2, fill: false
          };
        });

      trendChart = new Chart(trendEl, {
        type: 'line',
        data: { labels: data.labels, datasets: datasets },
        options: {
          responsive: true,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: { labels: { color: tc.text, boxWidth: 10, padding: 16, font: { size: 11 } } }
          },
          scales: {
            x: { ticks: { color: tc.text, font: { size: 10 } }, grid: { color: tc.grid } },
            y: { ticks: { color: tc.text, stepSize: 1, font: { size: 10 } }, grid: { color: tc.grid }, beginAtZero: true }
          }
        }
      });
    }

    // Doughnut chart
    var distEl = document.getElementById('severity-dist');
    if (distEl) {
      if (doughnutChart) doughnutChart.destroy();
      var ls = data.latest_severity;
      var entries = Object.entries(ls).filter(function(e) { return e[1] > 0; });
      if (entries.length) {
        doughnutChart = new Chart(distEl, {
          type: 'doughnut',
          data: {
            labels: entries.map(function(e) { return e[0].charAt(0).toUpperCase() + e[0].slice(1); }),
            datasets: [{
              data: entries.map(function(e) { return e[1]; }),
              backgroundColor: entries.map(function(e) { return sevColors[e[0]]; }),
              borderColor: tc.cardBg,
              borderWidth: 3
            }]
          },
          options: {
            responsive: true, cutout: '65%',
            plugins: {
              legend: { position: 'bottom', labels: { color: tc.text, padding: 14, font: { size: 11 } } }
            }
          }
        });
      }
    }
  }

  fetch('/api/website/' + encodeURIComponent(document.getElementById('website-page').dataset.hostname) + '/trends')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      trendsData = data;
      renderCharts(data);
    })
    .catch(function(err) { console.warn('Failed to load trends:', err); });

  // Re-render charts when theme changes
  new MutationObserver(function() {
    if (trendsData) renderCharts(trendsData);
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
})();
