<template>
	<course-deck :items="items" />
</template>

<script>
import CourseDeck from '~/components/CourseDeck.vue'
export default {
	components: {
		CourseDeck
	},
	computed: {
		items() {
			return this.$store.state.courses.list
		}
	}
}
</script>
