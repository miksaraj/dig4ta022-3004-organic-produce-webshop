<template>
	<div>
		<div v-for="sidebar in sidebars" :key="sidebar">
			<b-sidebar
				:id="sidebar"
				backdrop
				shadow
				:right="sidebar == 'sidebar-progress'"
			></b-sidebar>
		</div>
	</div>
</template>

<script>
export default {
	name: 'side-drawer',
	data() {
		return {
			sidebars: ['sidebar-contents', 'sidebar-progress']
		}
	}
}
</script>
