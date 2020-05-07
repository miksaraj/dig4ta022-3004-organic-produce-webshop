<template>
	<div>
		<h1>{{ item.header }}</h1>
		<!-- DUMMY CONTENT -->
		<theory-element />
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
import TheoryElement from '~/components/TheoryElement.vue'
export default {
	components: {
		TheoryElement
	},
	computed: {
		...mapGetters('sections', ['sectionById']),
		item() {
			return this.sectionById(this.itemId)
		},
		itemId() {
			return parseInt(this.$route.params.id)
		}
	}
}
</script>
