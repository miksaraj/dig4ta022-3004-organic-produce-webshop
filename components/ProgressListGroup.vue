<template>
	<div>
		<b-list-group v-for="item in items" :key="item.id">
			<progress-list-item :item="item" :theory="theory" />
		</b-list-group>
	</div>
</template>

<style scoped>
.list-group {
	padding-right: 1rem;
}
</style>

<script>
import ProgressListItem from '~/components/ProgressListItem.vue'
export default {
	name: 'ProgressListGroup',
	components: {
		ProgressListItem
	},
	computed: {
		items() {
			return this.$attrs.items
		},
		level() {
			return this.$attrs.level
		},
		theory() {
			return this.$attrs.theory
		}
	}
}
</script>
