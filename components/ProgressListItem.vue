<template>
	<b-list-group-item>
		{{ item.header }}
		<b-icon v-if="done" icon="check-circle" />
	</b-list-group-item>
</template>

<style scoped>
.b-icon {
	float: right;
	color: var(--color-3);
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'ProgressListItem',
	computed: {
		...mapGetters({
			isRead: 'progress/isRead',
			isDone: 'progress/isDone'
		}),
		item() {
			return this.$attrs.item
		},
		theory() {
			return this.$attrs.theory
		},
		done() {
			return this.theory
				? this.isRead(this.item.id)
				: this.isDone(this.item.id)
		}
	}
}
</script>
