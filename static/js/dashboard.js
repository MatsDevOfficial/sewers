let projects = [];
let currentProject = null;
let isEditMode = false;
let hackatimeProjects = [];

const projectsGrid = document.getElementById('projectsGrid');
const createProjectBtn = document.getElementById('createProjectBtn');
const createProjectModal = new bootstrap.Modal(document.getElementById('createProjectModal'));
const projectModal = new bootstrap.Modal(document.getElementById('projectModal'));
const submitChecklistModal = new bootstrap.Modal(document.getElementById('submitChecklistModal'));

const createProjectTitle = document.getElementById('createProjectTitle');
const createProjectDesc = document.getElementById('createProjectDesc');
const createGithubInput = document.getElementById('createGithubInput');
const createDemoInput = document.getElementById('createDemoInput');
const createHackatimeDropdown = document.getElementById('createHackatimeDropdown');
const createSelectedProjectsText = document.getElementById('createSelectedProjectsText');
const createHackatimeList = document.getElementById('createHackatimeList');
const createProjectSaveBtn = document.getElementById('createProjectSaveBtn');

const projectModalLabel = document.getElementById('projectModalLabel');
const projectTitleInput = document.getElementById('projectTitleInput');
const projectModalHours = document.getElementById('projectModalHours');
const projectModalBadge = document.getElementById('projectModalBadge');
const projectDescText = document.getElementById('projectDescText');
const projectDescInput = document.getElementById('projectDescInput');
const githubInput = document.getElementById('githubInput');
const demoInput = document.getElementById('demoInput');
const hackatimeDropdown = document.getElementById('hackatimeDropdown');
const selectedProjectsText = document.getElementById('selectedProjectsText');
const hackatimeList = document.getElementById('hackatimeList');

const editBtn = document.getElementById('editBtn');
const saveBtn = document.getElementById('saveBtn');
const submitBtn = document.getElementById('submitBtn');
const deleteBtn = document.getElementById('deleteBtn');
const finalSubmitBtn = document.getElementById('finalSubmitBtn');
const cancelEditBtn = document.getElementById('cancelEditBtn');

const checkHours = document.getElementById('checkHours');
const checkDemo = document.getElementById('checkDemo');
const checkGithub = document.getElementById('checkGithub');
const checkReadme = document.getElementById('checkReadme');
const checkBanner = document.getElementById('checkBanner');
const checkShippable = document.getElementById('checkShippable');

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
    const projectsResponse = await fetch('/api/projects');
    const projectsData = await projectsResponse.json();
    projects = projectsData.projects || [];
    
    const hackatimeResponse = await fetch('/api/hackatime');
    const hackatimeData = await hackatimeResponse.json();
    hackatimeProjects = hackatimeData?.data?.projects || [];
    
    renderProjects();
    populateHackatimeDropdowns();
  } catch (error) {
    projectsGrid.innerHTML = '<div class="col-12 text-center py-5"><p class="text-danger">Failed to load projects. Please try again.</p></div>';
    console.error('Failed to load projects:', error);
  }
}

function populateHackatimeDropdowns() {
  createHackatimeList.innerHTML = '';
  hackatimeList.innerHTML = '';
  
  hackatimeProjects.forEach(proj => {
    const name = proj.name || 'Unnamed';
    const hours = proj.text || '0m';
    const item = `
      <li>
        <a class="dropdown-item" href="#">
          <div class="form-check">
            <input class="form-check-input hackatime-checkbox-create" type="checkbox" value="${name}" id="create_${name}"/>
            <label class="form-check-label w-100" for="create_${name}">${name} (${hours})</label>
          </div>
        </a>
      </li>
    `;
    createHackatimeList.innerHTML += item;
    
    const editItem = `
      <li>
        <a class="dropdown-item" href="#">
          <div class="form-check">
            <input class="form-check-input hackatime-checkbox-edit" type="checkbox" value="${name}" id="edit_${name}"/>
            <label class="form-check-label w-100" for="edit_${name}">${name} (${hours})</label>
          </div>
        </a>
      </li>
    `;
    hackatimeList.innerHTML += editItem;
  });
  
  document.querySelectorAll('.hackatime-checkbox-create').forEach(cb => {
    cb.addEventListener('change', () => {
      updateCreateSelectedText();
      validateCreateForm();
    });
    cb.closest('.dropdown-item').addEventListener('click', function(e) {
      e.stopPropagation();
      if (e.target !== cb) {
        cb.checked = !cb.checked;
        updateCreateSelectedText();
        validateCreateForm();
      }
    });
  });
  
  document.querySelectorAll('.hackatime-checkbox-edit').forEach(cb => {
    cb.addEventListener('change', updateEditSelectedText);
    cb.closest('.dropdown-item').addEventListener('click', function(e) {
      e.stopPropagation();
      if (e.target !== cb) {
        cb.checked = !cb.checked;
        updateEditSelectedText();
      }
    });
  });
}

function renderProjects() {
  projectsGrid.innerHTML = '';
  
  if (projects.length === 0) {
    projectsGrid.innerHTML = '<div class="col-12 text-center py-5"><p class="text-muted">No projects yet. Create your first project!</p></div>';
    return;
  }
  
  projects.forEach(project => {
    const col = document.createElement('div');
    col.className = 'col';
    
    const id = project.id;
    const title = project.title || 'Untitled Project';
    const description = project.description || 'No description';
    const status = project.status || 'Building';
    const hours = project.hours || 0;
    const statusClass = getStatusBadge(status);
    
    col.innerHTML = `
      <div class="card h-100 shadow border-0 rounded-3">
        <div class="card-body d-flex flex-column">
          <div class="d-flex justify-content-between align-items-start mb-2">
            <h5 class="card-title mb-0 text-truncate">${title}</h5>
            <span class="badge ${statusClass}">${status}</span>
          </div>
          <p class="card-text text-truncate">${description}</p>
          <div class="d-flex justify-content-between align-items-center mt-auto">
            <h6 class="text-muted mb-0">${formatHours(hours)}</h6>
            <button type="button" class="btn btn-outline-primary btn-sm" data-project-id="${id}">View Project</button>
          </div>
        </div>
      </div>
    `;
    
    col.querySelector('button').addEventListener('click', () => openProjectModal(project));
    projectsGrid.appendChild(col);
  });
}

function openProjectModal(project) {
  currentProject = project;
  isEditMode = false;
  
  const id = project.id;
  const title = project.title || 'Untitled Project';
  const description = project.description || 'No description';
  const demoLink = project.demo_link || '';
  const githubLink = project.github_link || '';
  const hackatimeProject = project.hackatime_project || '';
  const status = project.status || 'Building';
  const hours = project.hours || 0;
  
  projectModalLabel.textContent = title;
  projectTitleInput.value = title;
  projectModalHours.textContent = formatHours(hours);
  projectModalBadge.className = 'badge ' + getStatusBadge(status);
  projectModalBadge.textContent = status;
  projectDescText.textContent = description;
  projectDescInput.value = description;
  githubInput.value = githubLink;
  demoInput.value = demoLink;
  
  setHackatimeProjects(hackatimeProject);
  toggleEditMode(false);
  
  if (status === 'Pending Review' || status === 'Shipped' || status === 'Approved') {
    submitBtn.style.display = 'none';
    editBtn.style.display = 'none';
  } else if (status === 'Building') {
    submitBtn.style.display = '';
    editBtn.style.display = '';
  } else {
    submitBtn.style.display = 'none';
    editBtn.style.display = 'none';
  }
  
  projectModal.show();
}

function openCreateProjectModal() {
  createProjectTitle.value = '';
  createProjectDesc.value = '';
  createGithubInput.value = '';
  createDemoInput.value = '';
  
  document.querySelectorAll('.hackatime-checkbox-create').forEach(cb => cb.checked = false);
  updateCreateSelectedText();
  validateCreateForm();
  
  createProjectModal.show();
}

function validateCreateForm() {
  const hasTitle = createProjectTitle.value.trim() !== '';
  const hasDesc = createProjectDesc.value.trim() !== '';
  const hasHackatime = getHackatimeProjects(true) !== '';
  
  const isValid = hasTitle && hasDesc && hasHackatime;
  createProjectSaveBtn.disabled = !isValid;
}

function toggleEditMode(edit) {
  isEditMode = edit;
  
  if (edit) {
    projectModalLabel.style.display = 'none';
    projectTitleInput.style.display = '';
    projectDescText.style.display = 'none';
    projectDescInput.style.display = '';
    githubInput.removeAttribute('readonly');
    demoInput.removeAttribute('readonly');
    hackatimeDropdown.removeAttribute('disabled');
    editBtn.style.display = 'none';
    submitBtn.style.display = 'none';
    cancelEditBtn.style.display = '';
    saveBtn.style.display = '';
  } else {
    projectTitleInput.style.display = 'none';
    projectModalLabel.style.display = '';
    projectDescInput.style.display = 'none';
    projectDescText.style.display = '';
    githubInput.setAttribute('readonly', true);
    demoInput.setAttribute('readonly', true);
    hackatimeDropdown.setAttribute('disabled', true);
    saveBtn.style.display = 'none';
    cancelEditBtn.style.display = 'none';
    editBtn.style.display = '';
    
    if (currentProject && currentProject.status === 'Building') {
      submitBtn.style.display = '';
    }
  }
}

function setHackatimeProjects(projectString) {
  const projectNames = projectString ? projectString.split(',').map(p => p.trim()) : [];
  document.querySelectorAll('.hackatime-checkbox-edit').forEach(cb => {
    cb.checked = projectNames.includes(cb.value);
  });
  updateEditSelectedText();
}

function getHackatimeProjects(isCreate) {
  const selector = isCreate ? '.hackatime-checkbox-create' : '.hackatime-checkbox-edit';
  const selected = Array.from(document.querySelectorAll(selector))
    .filter(cb => cb.checked)
    .map(cb => cb.value);
  return selected.join(', ');
}

function updateCreateSelectedText() {
  const selected = Array.from(document.querySelectorAll('.hackatime-checkbox-create'))
    .filter(cb => cb.checked)
    .map(cb => cb.value);
  
  if (selected.length === 0) {
    createSelectedProjectsText.textContent = 'Select projects...';
    createSelectedProjectsText.classList.add('text-muted');
  } else {
    createSelectedProjectsText.textContent = selected.join(', ');
    createSelectedProjectsText.classList.remove('text-muted');
  }
}

function updateEditSelectedText() {
  const selected = Array.from(document.querySelectorAll('.hackatime-checkbox-edit'))
    .filter(cb => cb.checked)
    .map(cb => cb.value);
  
  if (selected.length === 0) {
    selectedProjectsText.textContent = 'Select projects...';
    selectedProjectsText.classList.add('text-muted');
  } else {
    selectedProjectsText.textContent = selected.join(', ');
    selectedProjectsText.classList.remove('text-muted');
  }
}

async function handleCreateProject() {
  createProjectSaveBtn.disabled = true;
  createProjectSaveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating...';
  
  const response = await fetch('/api/projects', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      title: createProjectTitle.value,
      description: createProjectDesc.value,
      demo_link: createDemoInput.value,
      github_link: createGithubInput.value,
      hackatime_project: getHackatimeProjects(true)
    })
  });
  
  if (response.ok) {
    createProjectModal.hide();
    window.location.reload();
  } else {
    createProjectSaveBtn.disabled = false;
    createProjectSaveBtn.textContent = 'Create Project';
    alert('Failed to create project');
  }
}

async function handleSave() {
  saveBtn.disabled = true;
  saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
  
  const response = await fetch(`/api/projects/${currentProject.id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      title: projectTitleInput.value,
      description: projectDescInput.value,
      demo_link: demoInput.value,
      github_link: githubInput.value,
      hackatime_project: getHackatimeProjects(false)
    })
  });
  
  if (response.ok) {
    projectModal.hide();
    window.location.reload();
  } else {
    saveBtn.disabled = false;
    saveBtn.textContent = 'Save';
    alert('Failed to save project');
  }
}

async function handleDelete() {
  if (!confirm('Are you sure you want to delete this project?')) return;
  
  deleteBtn.disabled = true;
  deleteBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Deleting...';
  
  const response = await fetch(`/api/projects/${currentProject.id}`, {
    method: 'DELETE'
  });
  
  if (response.ok) {
    projectModal.hide();
    window.location.reload();
  } else {
    deleteBtn.disabled = false;
    deleteBtn.textContent = 'Delete';
    alert('Failed to delete project');
  }
}

function handleSubmitClick() {
  const hours = currentProject.hours || 0;
  const hasDemo = !!currentProject.demo_link;
  const hasGithub = !!currentProject.github_link;
  
  checkHours.checked = hours >= 3;
  checkDemo.checked = hasDemo;
  checkGithub.checked = hasGithub;
  checkReadme.checked = false;
  checkBanner.checked = true;
  checkShippable.checked = false;
  
  checkAllChecked();
  submitChecklistModal.show();
}

async function handleFinalSubmit() {
  finalSubmitBtn.disabled = true;
  finalSubmitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Submitting...';
  
  const response = await fetch(`/api/projects/${currentProject.id}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      status: 'Pending Review'
    })
  });
  
  if (response.ok) {
    submitChecklistModal.hide();
    projectModal.hide();
    window.location.reload();
  } else {
    finalSubmitBtn.disabled = false;
    finalSubmitBtn.textContent = 'Submit';
    alert('Failed to submit project');
  }
}

function checkAllChecked() {
  const allChecked = checkHours.checked && checkDemo.checked && checkGithub.checked && checkReadme.checked && checkBanner.checked && checkShippable.checked;
  finalSubmitBtn.disabled = !allChecked;
}

document.addEventListener('DOMContentLoaded', function() {
  loadProjects();
  
  createProjectBtn.addEventListener('click', openCreateProjectModal);
  createProjectSaveBtn.addEventListener('click', handleCreateProject);
  
  createProjectTitle.addEventListener('input', validateCreateForm);
  createProjectDesc.addEventListener('input', validateCreateForm);
  
  editBtn.addEventListener('click', () => toggleEditMode(true));
  cancelEditBtn.addEventListener('click', () => {
    projectTitleInput.value = currentProject.title || 'Untitled Project';
    projectDescInput.value = currentProject.description || 'No description';
    githubInput.value = currentProject.github_link || '';
    demoInput.value = currentProject.demo_link || '';
    setHackatimeProjects(currentProject.hackatime_project || '');
    toggleEditMode(false);
  });
  saveBtn.addEventListener('click', handleSave);
  deleteBtn.addEventListener('click', handleDelete);
  submitBtn.addEventListener('click', handleSubmitClick);
  finalSubmitBtn.addEventListener('click', handleFinalSubmit);
  
  checkHours.addEventListener('change', checkAllChecked);
  checkDemo.addEventListener('change', checkAllChecked);
  checkGithub.addEventListener('change', checkAllChecked);
  checkReadme.addEventListener('change', checkAllChecked);
  checkShippable.addEventListener('change', checkAllChecked);
  
  const submitChecklistModalEl = document.getElementById('submitChecklistModal');
  submitChecklistModalEl.addEventListener('show.bs.modal', function() {
    this.style.zIndex = 1060;
    setTimeout(() => {
      const backdrops = document.querySelectorAll('.modal-backdrop');
      if (backdrops.length > 1) {
        backdrops[backdrops.length - 1].style.zIndex = 1059;
      }
    }, 0);
  });
});