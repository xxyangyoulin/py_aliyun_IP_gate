document.querySelectorAll("[data-ip-editor]").forEach((editor) => {
  const tags = editor.querySelector("[data-ip-tags]");
  const input = editor.querySelector("[data-ip-input]");
  const value = editor.parentElement.querySelector("[data-ip-value]");

  const feedback = editor.parentElement.querySelector("[data-ip-feedback]");

  const setFeedback = (message, type = "") => {
    feedback.textContent = message;
    feedback.className = `field-feedback ${type}`;
    editor.classList.toggle("invalid", type === "error-text");
  };

  const isIpv4 = (ip) => {
    const parts = ip.split(".");
    return parts.length === 4 && parts.every((part) => {
      return /^\d+$/.test(part) && String(Number(part)) === part && Number(part) <= 255;
    });
  };

  const sync = () => {
    value.value = [...tags.querySelectorAll("[data-ip]")]
      .map((tag) => tag.dataset.ip)
      .join(",");
    value.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const bindRemove = (tag) => {
    tag.querySelector("button").addEventListener("click", () => {
      tag.remove();
      sync();
      input.focus();
    });
  };

  const add = (rawValue) => {
    const candidates = rawValue
      .split(/[\s,，]+/)
      .map((ip) => ip.trim())
      .filter(Boolean);
    if (!candidates.length) {
      setFeedback("");
      return;
    }
    const invalid = candidates.filter((ip) => !isIpv4(ip));
    let added = 0;
    let duplicates = 0;

    candidates
      .filter(isIpv4)
      .forEach((ip) => {
        const exists = [...tags.querySelectorAll("[data-ip]")]
          .some((tag) => tag.dataset.ip === ip);
        if (exists) {
          duplicates += 1;
          return;
        }

        const tag = document.createElement("span");
        tag.className = "ip-tag editable";
        tag.dataset.ip = ip;
        tag.append(document.createTextNode(ip));
        const remove = document.createElement("button");
        remove.type = "button";
        remove.setAttribute("aria-label", `删除 ${ip}`);
        remove.textContent = "×";
        tag.append(remove);
        bindRemove(tag);
        tags.append(tag);
        added += 1;
      });
    input.value = invalid.join(", ");
    sync();
    if (invalid.length) {
      setFeedback(`无法添加：${invalid.join("、")} 不是有效 IPv4 地址`, "error-text");
    } else if (added) {
      setFeedback(`已添加 ${added} 个 IP${duplicates ? `，忽略 ${duplicates} 个重复项` : ""}`, "success");
    } else if (duplicates) {
      setFeedback("该 IP 已存在，无需重复添加", "error-text");
    } else {
      setFeedback("");
    }
  };

  tags.querySelectorAll("[data-ip]").forEach(bindRemove);
  editor.addEventListener("click", (event) => {
    if (!event.target.closest("button")) input.focus();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === "," || event.key === "，") {
      event.preventDefault();
      add(input.value);
    } else if (event.key === "Backspace" && !input.value) {
      tags.lastElementChild?.remove();
      sync();
    }
  });
  input.addEventListener("blur", () => add(input.value));
  input.addEventListener("paste", (event) => {
    const pasted = event.clipboardData.getData("text");
    if (/[,，\s]/.test(pasted)) {
      event.preventDefault();
      add(pasted);
    }
  });
  input.addEventListener("input", () => {
    if (editor.classList.contains("invalid")) setFeedback("");
  });
  editor.closest("form").addEventListener("submit", (event) => {
    if (!input.value.trim()) return;
    add(input.value);
    if (input.value.trim()) {
      event.preventDefault();
      input.focus();
    }
  });
});

document.querySelectorAll("[data-target-editor]").forEach((editor) => {
  const type = editor.dataset.targetEditor;
  const tags = editor.querySelector("[data-target-tags]");
  const input = editor.querySelector("[data-target-input]");
  const value = editor.parentElement.querySelector(
    `[data-target-list][name="${type === "ecs" ? "security_groups" : "rds_instances"}"]`
  );
  const feedback = editor.parentElement.querySelector(`[data-target-feedback="${type}"]`);

  const setFeedback = (message, feedbackType = "") => {
    feedback.textContent = message;
    feedback.className = `field-feedback ${feedbackType}`;
    editor.classList.toggle("invalid", feedbackType === "error-text");
  };

  const isValid = (target) => type === "ecs"
    ? /^[a-z0-9-]+:sg-[a-z0-9-]+$/i.test(target)
    : /^rm-[a-z0-9-]+$/i.test(target);

  const consoleUrl = (target) => {
    if (type === "ecs") {
      const region = target.split(":", 1)[0];
      return `https://ecs.console.aliyun.com/securityGroup/region/${encodeURIComponent(region)}`;
    }
    return `https://rdsnext.console.aliyun.com/detail/${encodeURIComponent(target)}/basicInfo`;
  };

  const sync = () => {
    value.value = [...tags.querySelectorAll("[data-target-value]")]
      .map((tag) => tag.dataset.targetValue)
      .join(",");
    value.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const bindRemove = (tag) => {
    tag.querySelector("button").addEventListener("click", () => {
      tag.remove();
      sync();
      setFeedback("已移除目标", "success");
      input.focus();
    });
  };

  const createTag = (target) => {
    const tag = document.createElement("span");
    tag.className = "target-tag";
    tag.dataset.targetValue = target;
    const text = document.createElement("span");
    text.textContent = target;
    const link = document.createElement("a");
    link.href = consoleUrl(target);
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.title = "在阿里云控制台查看";
    link.textContent = "↗";
    const remove = document.createElement("button");
    remove.type = "button";
    remove.setAttribute("aria-label", `删除 ${target}`);
    remove.textContent = "×";
    tag.append(text, link, remove);
    bindRemove(tag);
    tags.append(tag);
  };

  const add = (rawValue) => {
    const candidates = rawValue.split(/[\s,，]+/).map((item) => item.trim()).filter(Boolean);
    if (!candidates.length) {
      setFeedback("");
      return;
    }
    const invalid = candidates.filter((target) => !isValid(target));
    let added = 0;
    let duplicates = 0;
    candidates.filter(isValid).forEach((target) => {
      const exists = [...tags.querySelectorAll("[data-target-value]")]
        .some((tag) => tag.dataset.targetValue === target);
      if (exists) {
        duplicates += 1;
      } else {
        createTag(target);
        added += 1;
      }
    });
    input.value = invalid.join(", ");
    sync();
    if (invalid.length) {
      const example = type === "ecs" ? "cn-chengdu:sg-example" : "rm-example";
      setFeedback(`格式错误：${invalid.join("、")}；正确示例 ${example}`, "error-text");
    } else if (added) {
      setFeedback(`已添加 ${added} 个目标${duplicates ? `，忽略 ${duplicates} 个重复项` : ""}`, "success");
    } else {
      setFeedback("该目标已存在，无需重复添加", "error-text");
    }
  };

  tags.querySelectorAll("[data-target-value]").forEach(bindRemove);
  editor.addEventListener("click", (event) => {
    if (!event.target.closest("a, button")) input.focus();
  });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === "," || event.key === "，") {
      event.preventDefault();
      add(input.value);
    } else if (event.key === "Backspace" && !input.value) {
      tags.lastElementChild?.remove();
      sync();
    }
  });
  input.addEventListener("blur", () => add(input.value));
  input.addEventListener("paste", (event) => {
    const pasted = event.clipboardData.getData("text");
    if (/[,，\s]/.test(pasted)) {
      event.preventDefault();
      add(pasted);
    }
  });
  input.addEventListener("input", () => {
    if (editor.classList.contains("invalid")) setFeedback("");
  });
  editor.closest("form").addEventListener("submit", (event) => {
    if (!input.value.trim()) return;
    add(input.value);
    if (input.value.trim()) {
      event.preventDefault();
      input.focus();
    }
  });
});

document.querySelectorAll("[data-local-time]").forEach((element) => {
  const original = element.dateTime;
  const date = new Date(original);
  if (Number.isNaN(date.getTime())) return;

  element.textContent = new Intl.DateTimeFormat(navigator.language, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
  element.title = original;
});

document.querySelectorAll("[data-relative-time]").forEach((element) => {
  const seconds = Math.round((new Date(element.dataset.relativeTime) - new Date()) / 1000);
  const ranges = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [30, "day"],
    [12, "month"],
    [Infinity, "year"],
  ];
  let value = seconds;
  for (const [limit, unit] of ranges) {
    if (Math.abs(value) < limit) {
      element.textContent = new Intl.RelativeTimeFormat(navigator.language, { numeric: "auto" }).format(value, unit);
      break;
    }
    value = Math.round(value / limit);
  }
});

document.querySelectorAll("[data-password-toggle]").forEach((button) => {
  button.addEventListener("click", async () => {
    const input = button.parentElement.querySelector("input");
    const showing = input.type === "text";
    if (showing) {
      input.type = "password";
      if (input.dataset.revealed === "true") {
        input.value = "";
        delete input.dataset.revealed;
      }
      button.textContent = "显示";
      button.setAttribute("aria-label", "显示敏感信息");
      return;
    }

    if (!input.value && button.dataset.revealSecret) {
      const form = button.closest("form");
      const csrfToken = form.querySelector('[name="csrf_token"]').value;
      const body = new URLSearchParams({
        csrf_token: csrfToken,
        secret_name: button.dataset.revealSecret,
      });
      if (button.dataset.accountId) body.set("account_id", button.dataset.accountId);
      button.disabled = true;
      button.textContent = "读取中";
      try {
        const response = await fetch("/secrets/reveal", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body,
        });
        if (!response.ok) throw new Error("读取失败");
        input.value = (await response.json()).value;
        input.dataset.revealed = "true";
      } catch (error) {
        button.textContent = "读取失败";
        setTimeout(() => { button.textContent = "显示"; }, 1500);
        return;
      } finally {
        button.disabled = false;
      }
    }

    input.type = "text";
    button.textContent = "隐藏";
    button.setAttribute("aria-label", "隐藏敏感信息");
  });
});

document.querySelectorAll("[data-sync-form]").forEach((form) => {
  form.addEventListener("submit", () => {
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    button.classList.add("loading");
    button.querySelector("[data-button-label]").textContent = "正在同步…";
  });
});

document.querySelectorAll("[data-toast]").forEach((toast) => {
  const close = () => {
    toast.classList.add("closing");
    setTimeout(() => toast.remove(), 180);
  };
  toast.querySelector("[data-toast-close]").addEventListener("click", close);
  setTimeout(close, 5000);
});

const dirtyForms = new Set();
document.querySelectorAll("[data-dirty-check]").forEach((form) => {
  form.addEventListener("input", () => dirtyForms.add(form));
  form.addEventListener("change", () => dirtyForms.add(form));
  form.addEventListener("submit", (event) => {
    if (!event.defaultPrevented) dirtyForms.delete(form);
  });
});
window.addEventListener("beforeunload", (event) => {
  if (!dirtyForms.size) return;
  event.preventDefault();
  event.returnValue = "";
});

const openNavigation = () => document.body.classList.add("nav-open");
const closeNavigation = () => document.body.classList.remove("nav-open");
document.querySelector("[data-nav-open]")?.addEventListener("click", openNavigation);
document.querySelectorAll("[data-nav-close]").forEach((button) => button.addEventListener("click", closeNavigation));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeNavigation();
});

document.querySelectorAll("[data-run-filter]").forEach((button) => {
  button.addEventListener("click", () => {
    const filter = button.dataset.runFilter;
    document.querySelectorAll("[data-run-filter]").forEach((item) => item.classList.toggle("active", item === button));
    document.querySelectorAll("[data-run-status]").forEach((row) => {
      row.hidden = filter !== "all" && row.dataset.runStatus !== filter;
    });
  });
});

document.querySelectorAll("[data-copy-target]").forEach((button) => {
  button.addEventListener("click", async () => {
    const text = document.getElementById(button.dataset.copyTarget).textContent;
    await navigator.clipboard.writeText(text);
    button.textContent = "已复制";
    setTimeout(() => { button.textContent = "复制代码"; }, 1600);
  });
});

const confirmDialog = document.querySelector("[data-confirm-dialog]");
let pendingForm = null;
document.querySelectorAll("form[data-confirm]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (form.dataset.confirmed === "true") return;
    event.preventDefault();
    pendingForm = form;
    confirmDialog.querySelector("[data-confirm-title]").textContent = form.dataset.confirmTitle || "确认操作";
    confirmDialog.querySelector("[data-confirm-message]").textContent = form.dataset.confirm;
    confirmDialog.showModal();
  });
});
confirmDialog?.addEventListener("close", () => {
  if (confirmDialog.returnValue === "confirm" && pendingForm) {
    pendingForm.dataset.confirmed = "true";
    pendingForm.requestSubmit();
  }
  pendingForm = null;
});

const guideDialog = document.querySelector("[data-guide-dialog]");
document.querySelector("[data-guide-open]")?.addEventListener("click", () => guideDialog.showModal());
document.querySelector("[data-guide-close]")?.addEventListener("click", () => guideDialog.close());
guideDialog?.addEventListener("click", (event) => {
  if (event.target === guideDialog) guideDialog.close();
});

const renderResourceResults = (dialog, result) => {
  const message = dialog.querySelector("[data-result-message]");
  const container = dialog.querySelector("[data-resource-results]");
  message.textContent = result.message || (result.success ? "检查完成，所有资源均可正常读取。" : "检查完成，部分资源存在问题。");
  container.replaceChildren();

  if (!result.resources?.length) {
    const empty = document.createElement("div");
    empty.className = "result-loading";
    empty.textContent = result.message || "没有可检查的云端资源";
    container.append(empty);
    return;
  }

  result.resources.forEach((resource) => {
    const item = document.createElement("div");
    item.className = `resource-result ${resource.success ? "" : "failed"}`;
    const type = document.createElement("span");
    type.textContent = resource.resource_type;
    const content = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = `${resource.account_name} / ${resource.resource_id}`;
    const detail = document.createElement("p");
    detail.textContent = resource.message;
    content.append(name, detail);
    const status = document.createElement("span");
    status.className = `status ${resource.success ? (resource.action === "unchanged" ? "stopped" : "success") : "failed"}`;
    status.textContent = resource.success ? (resource.action === "checked" ? "通过" : resource.action === "unchanged" ? "无需变更" : "将变更") : "失败";
    item.append(type, content, status);
    container.append(item);
  });
};

document.querySelectorAll(".result-dialog").forEach((dialog) => {
  dialog.querySelector("[data-result-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
});

document.querySelectorAll("[data-account-test]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    const dialog = document.querySelector("[data-account-test-dialog]");
    dialog.querySelector("[data-result-title]").textContent = `${form.dataset.accountName} 连接测试`;
    dialog.querySelector("[data-result-message]").textContent = "正在验证凭证和资源读取权限…";
    dialog.querySelector("[data-resource-results]").innerHTML = '<div class="result-loading">正在连接阿里云，请稍候…</div>';
    dialog.showModal();
    button.disabled = true;
    button.textContent = "测试中…";
    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new URLSearchParams(new FormData(form)),
      });
      renderResourceResults(dialog, await response.json());
    } catch (error) {
      renderResourceResults(dialog, { success: false, message: "请求失败，请检查 Web 服务状态。", resources: [] });
    } finally {
      button.disabled = false;
      button.textContent = "测试连接";
    }
  });
});

document.querySelector("[data-sync-preview]")?.addEventListener("click", async (event) => {
  const button = event.currentTarget;
  const dialog = document.querySelector("[data-preview-dialog]");
  const csrfToken = document.querySelector('[data-sync-form] [name="csrf_token"]').value;
  dialog.querySelector("[data-result-message]").textContent = "正在读取公网 IP 和云端配置…";
  dialog.querySelector("[data-resource-results]").innerHTML = '<div class="result-loading">只读检查中，不会修改任何云端规则…</div>';
  dialog.querySelector("[data-preview-ips]").replaceChildren();
  dialog.showModal();
  button.disabled = true;
  button.textContent = "预览中…";
  try {
    const response = await fetch("/sync/preview", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ csrf_token: csrfToken }),
    });
    const result = await response.json();
    const ipArea = dialog.querySelector("[data-preview-ips]");
    if (result.target_ips?.length) {
      const label = document.createElement("span");
      label.textContent = "本轮目标 IP";
      const tags = document.createElement("div");
      tags.className = "ip-tags";
      result.target_ips.forEach((ip) => {
        const tag = document.createElement("span");
        tag.className = "ip-tag";
        tag.textContent = ip;
        tags.append(tag);
      });
      ipArea.append(label, tags);
    }
    renderResourceResults(dialog, result);
  } catch (error) {
    renderResourceResults(dialog, { success: false, message: "预览失败，请检查 Web 服务状态。", resources: [] });
  } finally {
    button.disabled = false;
    button.textContent = "预览变更";
  }
});
