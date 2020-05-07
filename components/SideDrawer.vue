<template>
	<div>
		<div v-for="sidebar in sidebars" :key="sidebar">
			<b-sidebar
				:id="sidebar"
				backdrop
				shadow
				:right="sidebar == 'sidebar-progress'"
			>
				<sidebar-contents v-if="sidebar == 'sidebar-contents'" />
				<sidebar-progress v-if="sidebar == 'sidebar-progress'" />
			</b-sidebar>
		</div>
	</div>
</template>

<script>
import SidebarContents from '~/components/SidebarContents.vue'
import SidebarProgress from '~/components/SidebarProgress.vue'
export default {
	name: 'sideDrawer',
	components: {
		SidebarContents,
		SidebarProgress
	},
	data() {
		return {
			sidebars: ['sidebar-contents', 'sidebar-progress']
		}
	}
}
</script>
