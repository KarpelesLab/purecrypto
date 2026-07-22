<script setup>
defineProps({
  index: String,
  title: String,
  subtitle: String,
  api: String,
});
</script>

<template>
  <article class="demo panel">
    <header class="demo-head">
      <div>
        <span class="idx mono">{{ index }}</span>
        <h3>{{ title }}</h3>
        <p class="sub">{{ subtitle }}</p>
      </div>
      <slot name="badge" />
    </header>
    <div class="demo-body">
      <slot />
    </div>
    <footer v-if="api" class="demo-foot mono">{{ api }}</footer>
  </article>
</template>

<style scoped>
.demo {
  padding: 26px;
  display: flex;
  flex-direction: column;
}
.demo-head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 22px;
}
.idx {
  font-size: 0.74rem;
  color: var(--violet-2);
  letter-spacing: 0.14em;
}
.demo-head h3 {
  font-size: 1.32rem;
  margin: 8px 0 6px;
}
.sub {
  color: var(--muted);
  font-size: 0.92rem;
  margin: 0;
  max-width: 40em;
}
.demo-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
  flex: 1;
}
.demo-foot {
  margin-top: 22px;
  padding-top: 16px;
  border-top: 1px solid var(--line-soft);
  font-size: 0.74rem;
  color: var(--muted);
}
</style>
