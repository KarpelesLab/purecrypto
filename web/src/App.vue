<script setup>
import SiteNav from './components/SiteNav.vue';
import HeroSection from './components/HeroSection.vue';
import CapabilityMatrix from './components/CapabilityMatrix.vue';
import DemosSection from './components/DemosSection.vue';
import PrinciplesSection from './components/PrinciplesSection.vue';
import SiteFooter from './components/SiteFooter.vue';
</script>

<template>
  <div class="field" aria-hidden="true"></div>
  <SiteNav />
  <main>
    <HeroSection />
    <CapabilityMatrix />
    <DemosSection />
    <PrinciplesSection />
  </main>
  <SiteFooter />
</template>

<style>
/* Ambient field: a faint lattice that anchors the "post-quantum" motif without
   competing with content. Sits behind everything, fixed. */
.field {
  position: fixed;
  inset: 0;
  z-index: -1;
  background:
    radial-gradient(900px 600px at 78% -8%, rgba(139, 108, 255, 0.14), transparent 60%),
    radial-gradient(760px 520px at 8% 4%, rgba(47, 224, 200, 0.08), transparent 55%),
    linear-gradient(180deg, #0a0c16, var(--ink) 40%);
}
.field::after {
  content: '';
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(120, 130, 180, 0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(120, 130, 180, 0.05) 1px, transparent 1px);
  background-size: 46px 46px;
  mask-image: radial-gradient(1100px 700px at 50% 0%, #000 30%, transparent 78%);
}
main {
  position: relative;
}
</style>
