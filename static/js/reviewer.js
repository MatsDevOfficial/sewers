let projects = [];
let currentProject = null;
const projectModal = new bootstrap.Modal(document.getElementById('projectModal'));

const pendingGrid = document.getElementById('pendingGrid');
const shippedGrid = document.getElementById('shippedGrid');
const buildingGrid = document.getElementById('buildingGrid');
const pendingCount = document.getElementById('pendingCount');
const shippedCount = document.getElementById('shippedCount');
const buildingCount = document.getElementById('buildingCount');

const projectModalLabel = document.getElementById('projectModalLabel');
const projectModalBadge = document.getElementById('projectModalBadge');
const projectModalHours = document.getElementById('projectModalHours');
const projectDescText = document.getElementById('projectDescText');
const demoInput = document.getElementById('demoInput');
const githubInput = document.getElementById('githubInput');
const hackatimeInput = document.getElementById('hackatimeInput');
const creatorLink = document.getElementById('creatorLink');
const approveBtn = document.getElementById('approveBtn');
const rejectBtn = document.getElementById('rejectBtn');

function getStatusBadge(status) {
  const statusMap = {
    'Building': 'bg-warning text-dark',
    'Pending Review': 'bg-info text-dark',
    'Approved': 'bg-success',
    'Shipped': 'bg-success',
    'Rejected': 'bg-danger'
  };
  return statusMap[status] || 'bg-secondary';
}

function formatHours(hours) {
  if (typeof hours === 'number') {
    const h = Math.floor(hours);
    const m = Math.round((hours - h) * 60);
    if (h === 0 && m === 0) return '0h 0m';
    if (h === 0) return `${m}m`;
    if (m === 0) return `${h}h`;
    return `${h}h ${m}m`;
  }
  return '0h 0m';
}

async function loadProjects() {
  try {
    const response = await fetch('/api/reviewer/projects');
    const data = await response.json();
    projects = data.projects || [];
    renderProjects();
  } catch (error) {
    console.error('Failed to load projects:', error);
  }
}

function renderProjects() {
  const pending = projects.filter(p => p.status === 'Pending Review');
  const shipped = projects.filter(p => p.status === 'Shipped' || p.status === 'Approved');
  const building = projects.filter(p => p.status === 'Building');
  
  pendingCount.textContent = `${pending.length} Project${pending.length !== 1 ? 's' : ''}`;
  shippedCount.textContent = `${shipped.length} Project${shipped.length !== 1 ? 's' : ''}`;
  buildingCount.textContent = `${building.length} Project${building.length !== 1 ? 's' : ''}`;
  
  renderGrid(pendingGrid, pending);
  renderGrid(shippedGrid, shipped);
  renderGrid(buildingGrid, building);
}

function renderGrid(grid, projectList) {
  grid.innerHTML = '';
  
  if (projectList.length === 0) {
    grid.innerHTML = '<div class="col-12 text-center py-3"><p class="text-muted">No projects</p></div>';
    return;
  }
  
  projectList.forEach(project => {
    const col = document.createElement('div');
    col.className = 'col';
    
    const title = project.title || 'Untitled Project';
    const description = project.description || 'No description';
    const status = project.status || 'Building';
    const hours = project.hours || 0;
    const nickname = project.nickname || project.email || 'Unknown';
    const statusClass = getStatusBadge(status);
    const buttonText = status === 'Pending Review' ? 'REVIEW PROJECT' : 'VIEW PROJECT';
    const buttonClass = status === 'Pending Review' ? 'btn-primary' : 'btn-outline-primary';
    
    col.innerHTML = `
      <div class="card h-100 shadow border-0 rounded-3">
        <div class="card-body d-flex flex-column">
          <div class="d-flex justify-content-between align-items-start mb-2">
            <h5 class="card-title mb-0 text-truncate">${title}</h5>
            <span class="badge ${statusClass}">${status}</span>
          </div>
          <p class="card-text text-truncate mb-2">${description}</p>
          <p class="text-muted small mb-2">By: <a href="https://google.com" target="_blank">${nickname}</a></p>
          <div class="d-flex justify-content-between align-items-center mt-auto">
            <h6 class="text-muted mb-0">${formatHours(hours)}</h6>
            <button type="button" class="btn ${buttonClass} btn-sm px-3" data-project-id="${project.id}">
              ${buttonText}
            </button>
          </div>
        </div>
      </div>
    `;
    
    col.querySelector('button').addEventListener('click', () => openProjectModal(project));
    grid.appendChild(col);
  });
}

function openProjectModal(project) {
  currentProject = project;
  
  const title = project.title || 'Untitled Project';
  const description = project.description || 'No description';
  const demoLink = project.demo_link || '';
  const githubLink = project.github_link || '';
  const hackatimeProject = project.hackatime_project || '';
  const status = project.status || 'Building';
  const hours = project.hours || 0;
  const nickname = project.nickname || project.email || 'Unknown';
  
  projectModalLabel.textContent = title;
  projectModalBadge.className = 'badge ' + getStatusBadge(status);
  projectModalBadge.textContent = status;
  projectModalHours.textContent = formatHours(hours);
  projectDescText.textContent = description;
  demoInput.value = demoLink;
  githubInput.value = githubLink;
  hackatimeInput.value = hackatimeProject;
  creatorLink.textContent = nickname;
  
  if (status === 'Pending Review') {
    approveBtn.style.display = '';
    rejectBtn.style.display = '';
  } else {
    approveBtn.style.display = 'none';
    rejectBtn.style.display = 'none';
  }
  
  projectModal.show();
}

async function handleApprove() {
  if (!currentProject) return;
  
  approveBtn.disabled = true;
  approveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Approving...';
  
  try {
    const response = await fetch(`/api/reviewer/projects/${currentProject.id}/approve`, {
      method: 'POST'
    });
    
    if (response.ok) {
      projectModal.hide();
      await loadProjects();
    } else {
      alert('Failed to approve project');
    }
  } catch (error) {
    console.error('Failed to approve:', error);
    alert('Failed to approve project');
  } finally {
    approveBtn.disabled = false;
    approveBtn.textContent = 'Approve';
  }
}

async function handleReject() {
  if (!currentProject) return;
  
  rejectBtn.disabled = true;
  rejectBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Rejecting...';
  
  try {
    const response = await fetch(`/api/reviewer/projects/${currentProject.id}/reject`, {
      method: 'POST'
    });
    
    if (response.ok) {
      projectModal.hide();
      await loadProjects();
    } else {
      alert('Failed to reject project');
    }
  } catch (error) {
    console.error('Failed to reject:', error);
    alert('Failed to reject project');
  } finally {
    rejectBtn.disabled = false;
    rejectBtn.textContent = 'Reject';
  }
}

document.addEventListener('DOMContentLoaded', function() {
  loadProjects();
  approveBtn.addEventListener('click', handleApprove);
  rejectBtn.addEventListener('click', handleReject);
});
