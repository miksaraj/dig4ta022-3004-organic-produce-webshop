<template>
	<b-card-group deck>
		<div v-for="item in items" :key="item.id">
			<assignment :item="item" />
		</div>
	</b-card-group>
</template>

<script>
import Assignment from '~/components/Assignment.vue'
export default {
	name: 'stats',
	components: {
		Assignment
	},
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
