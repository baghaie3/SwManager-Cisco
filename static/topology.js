let network;
let topologyData;

// تغییر آدرس API به مسیر Blueprint جدید
async function loadDevices(){
    let res = await fetch("/topology/devices")
    let data = await res.json();

    let box = document.getElementById("switch_list");
    box.innerHTML = "";

    data.forEach(d => {
        let div = document.createElement("div");
        div.className = "form-check";

        let chk = document.createElement("input");
        chk.type = "checkbox";
        chk.value = d.ip;
        chk.className = "form-check-input sw_chk";
        chk.id = "chk_" + d.ip;

        let lbl = document.createElement("label");
        lbl.className = "form-check-label";
        lbl.setAttribute("for", chk.id);
        lbl.innerText = d.name + " (" + d.ip + ")";

        div.appendChild(chk);
        div.appendChild(lbl);
        box.appendChild(div);
    });
}

function getSelected(){
    let boxes = document.querySelectorAll(".sw_chk");
    let ips = [];
    boxes.forEach(b => {
        if(b.checked) ips.push(b.value);
    });
    return ips;
}

function toggleSelectAll(master){
    const boxes = document.querySelectorAll(".sw_chk");
    boxes.forEach(b => b.checked = master.checked);
}

async function scan(){
    let devices = getSelected();

    if(devices.length === 0){
        alert("هیچ سوئیچی انتخاب نشده است.");
        return;
    }

    let protocol = document.getElementById("scan_protocol").value;

    let timer = setInterval(updateProgress,1000);

    let res = await fetch("/topology/scan",{
        method:"POST",
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
            devices:devices,
            protocol:protocol
        })
    });

    clearInterval(timer);

    let data = await res.json();

    if(!data.nodes || data.nodes.length === 0){
        alert("داده‌ای برای نمایش یافت نشد.");
        return;
    }

    drawTopology(data);
    updateProgress();
}

async function updateProgress(){

    let res = await fetch("/topology/progress");
    let data = await res.json();

    let bar = document.getElementById("progress_bar");

    bar.style.width = data.percent + "%";
    bar.innerText = data.percent + "%";
}

document.addEventListener("DOMContentLoaded",()=>{
    loadDevices();
});

function drawTopology(data){

    topologyData = data;

    const container = document.getElementById("topology_container");

    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

    const graph = {
        nodes:nodes,
        edges:edges
    };

    const options = {

    layout:{
        hierarchical:{
            enabled:true,
            direction:"UD",
            sortMethod:"directed",
            levelSeparation:150,
            nodeSpacing:120
        }
    },

    physics:false,

    interaction:{
        dragNodes:true,
        hover:true
    },

    nodes:{
        shape:"dot",
        size:22,
        font:{
            size:22
        }
    },

    edges:{
        smooth:false
    }
}



	assignLevels(topologyData.nodes, topologyData.edges);
	
    network = new vis.Network(container,graph,options);

    network.once("stabilizationIterationsDone",function(){
        network.setOptions({physics:false});
    });
}

function exportTopology(){

    const canvas = document.querySelector("#topology_container canvas");

    const scale = 4;

    const exportCanvas = document.createElement("canvas");

    exportCanvas.width = canvas.width * scale;
    exportCanvas.height = canvas.height * scale;

    const ctx = exportCanvas.getContext("2d");

    ctx.scale(scale,scale);
    ctx.drawImage(canvas,0,0);

    const link = document.createElement("a");

    link.download = "network_topology.png";
    link.href = exportCanvas.toDataURL("image/png");

    link.click();
}


function findCore(nodes, edges) {

    const degree = {};
    nodes.forEach(n => degree[n.id] = 0);

    edges.forEach(e => {
        degree[e.from]++;
        degree[e.to]++;
    });

    let core = null;
    let max = -1;

    for (const id in degree) {
        if (degree[id] > max) {
            max = degree[id];
            core = id;
        }
    }

    return core;
}


function assignLevels(nodes, edges) {

    const core = findCore(nodes, edges);

    const adj = {};
    nodes.forEach(n => adj[n.id] = []);

    edges.forEach(e => {
        adj[e.from].push(e.to);
        adj[e.to].push(e.from);
    });

    const levels = {};
    const queue = [core];

    levels[core] = 0;

    while (queue.length) {

        const current = queue.shift();

        adj[current].forEach(nei => {

            if (levels[nei] === undefined) {

                levels[nei] = levels[current] + 1;
                queue.push(nei);

            }

        });
    }

    nodes.forEach(n => {
        n.level = levels[n.id] ?? 0;
    });

}



function exportSVG() {

    if (!network || !topologyData) return;

    const positions = network.getPositions();
    const nodes = topologyData.nodes;
    const edges = topologyData.edges;

    // محاسبه محدوده واقعی گراف
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;

    Object.values(positions).forEach(pos => {
        if (pos.x < minX) minX = pos.x;
        if (pos.y < minY) minY = pos.y;
        if (pos.x > maxX) maxX = pos.x;
        if (pos.y > maxY) maxY = pos.y;
    });

    const padding = 50;

    const width = (maxX - minX) + padding * 2;
    const height = (maxY - minY) + padding * 2;

    const offsetX = -minX + padding;
    const offsetY = -minY + padding;

    let svg = [];

    svg.push(`<svg xmlns="http://www.w3.org/2000/svg"
        width="${width}"
        height="${height}"
        viewBox="0 0 ${width} ${height}">`);

    // رسم لینک‌ها
    edges.forEach(edge => {

        const from = positions[edge.from];
        const to = positions[edge.to];

        if (!from || !to) return;

        svg.push(
            `<line x1="${from.x + offsetX}"
                   y1="${from.y + offsetY}"
                   x2="${to.x + offsetX}"
                   y2="${to.y + offsetY}"
                   stroke="black"
                   stroke-width="2"/>`
        );
    });

    // رسم نودها
    nodes.forEach(node => {

        const pos = positions[node.id];
        if (!pos) return;

        svg.push(
            `<circle cx="${pos.x + offsetX}"
                     cy="${pos.y + offsetY}"
                     r="12"
                     fill="#3498db"/>`
        );

        svg.push(
            `<text x="${pos.x + offsetX}"
                   y="${pos.y + offsetY + 25}"
                   font-size="12"
                   font-family="Arial"
                   text-anchor="middle">
                   ${node.label}
            </text>`
        );
    });

    svg.push(`</svg>`);

    const blob = new Blob([svg.join("")], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = "topology.svg";
    link.click();

    URL.revokeObjectURL(url);
}


function exportJPG() {
    if (!network) {
        alert("ابتدا باید نقشه را اسکن کنید!");
        return;
    }

    // فیت کردن نقشه برای اینکه همه سوئیچ‌ها در عکس بیفتند
    network.fit();

    // کمی صبر برای اتمام رندر انیمیشن فیت شدن
    setTimeout(() => {
        const canvas = document.querySelector('#topology_container canvas');
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = canvas.width;
        tempCanvas.height = canvas.height;
        const ctx = tempCanvas.getContext('2d');

        // ۱. رنگ پس‌زمینه سفید
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, tempCanvas.width, tempCanvas.height);

        // ۲. کپی کردن محتویات گراف روی صفحه سفید
        ctx.drawImage(canvas, 0, 0);

        // ۳. دانلود فایل
        const link = document.createElement('a');
        link.download = "network_topology_" + new Date().getTime() + ".jpg";
        link.href = tempCanvas.toDataURL("image/jpeg", 0.9); // کیفیت ۹۰ درصد
        link.click();
    }, 500);
}

async function exportVisio() {
  if (!network || !topologyData) {
    alert("ابتدا توپولوژی را بارگذاری کنید.");
    return;
  }

  try {
    const positions = network.getPositions();
    const nodeMap = new Map((topologyData.nodes || []).map(n => [String(n.id), n]));

    const payload = {
      version: 1,
      exportedAt: new Date().toISOString(),
      title: "topology_visio",
      nodes: (topologyData.nodes || []).map(node => {
        const id = String(node.id);
        const pos = positions[id] || { x: 0, y: 0 };
        return {
          id: id,
          label: node.label || node.name || id,
          type: node.type || "device",
          x: pos.x,
          y: pos.y,
          shape: node.shape || "ellipse",
          color: node.color || null,
          group: node.group || null
        };
      }),
      edges: (topologyData.edges || []).map((edge, idx) => {
        const fromId = String(edge.from);
        const toId = String(edge.to);
        return {
          id: edge.id != null ? String(edge.id) : `e${idx + 1}`,
          from: fromId,
          to: toId,
          label: edge.label || "",
          arrows: edge.arrows || "to",
          smooth: edge.smooth || false,
          fromLabel: nodeMap.get(fromId)?.label || nodeMap.get(fromId)?.name || fromId,
          toLabel: nodeMap.get(toId)?.label || nodeMap.get(toId)?.name || toId
        };
      })
    };

    const res = await fetch("/topology/export_visio", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    if (!res.ok) {
      alert("خطا در گرفتن خروجی Visio");
      return;
    }

    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "topology_visio.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error(err);
    alert("خطا در گرفتن خروجی Visio");
  }
}


