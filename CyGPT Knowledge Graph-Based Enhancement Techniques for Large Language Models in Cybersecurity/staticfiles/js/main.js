/**
 * CyGPT Main JavaScript
 * Handles: toast auto-dismiss, animations, table interactions
 */

document.addEventListener('DOMContentLoaded', () => {

  // ── Auto-dismiss toasts ──────────────────────────────────────────────
  document.querySelectorAll('.toast.show').forEach(toastEl => {
    setTimeout(() => {
      const bsToast = bootstrap.Toast.getOrCreateInstance(toastEl);
      bsToast.hide();
    }, 4000);
  });

  // ── Staggered card entrance animation ────────────────────────────────
  const cards = document.querySelectorAll('.glass-card, .stat-card, .feature-card');
  cards.forEach((card, i) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(16px)';
    card.style.transition = 'opacity .4s ease, transform .4s ease';
    setTimeout(() => {
      card.style.opacity = '1';
      card.style.transform = 'translateY(0)';
    }, 60 + i * 40);
  });

  // ── Smooth scroll for anchor links ───────────────────────────────────
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // ── Confirm dangerous actions (non-delete buttons) ───────────────────
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', e => {
      if (!confirm(el.dataset.confirm)) e.preventDefault();
    });
  });

  // ── Navbar active link highlight ─────────────────────────────────────
  const currentPath = window.location.pathname;
  document.querySelectorAll('.cyber-nav-link').forEach(link => {
    if (link.getAttribute('href') && currentPath.startsWith(link.getAttribute('href')) && link.getAttribute('href') !== '/') {
      link.classList.add('text-cyan');
      link.style.background = 'rgba(0,198,255,.06)';
    }
  });

  // ── Progress bar animation on scroll ─────────────────────────────────
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.querySelectorAll('.progress-bar').forEach(bar => {
          const width = bar.style.width;
          bar.style.width = '0';
          setTimeout(() => { bar.style.transition = 'width .8s ease'; bar.style.width = width; }, 100);
        });
      }
    });
  }, { threshold: 0.3 });

  document.querySelectorAll('.glass-card').forEach(card => observer.observe(card));

});
