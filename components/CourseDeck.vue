<template>
	<b-card-group deck>
		<div v-for="item in items" :key="item.id">
			<course :item="item" />
		</div>
	</b-card-group>
</template>

<script>
import Course from '~/components/Course.vue'
export default {
	name: 'course-deck',
	components: {
		Course
	},
	computed: {
		items() {
			return this.$attrs.items
		}
	}
}
</script>
