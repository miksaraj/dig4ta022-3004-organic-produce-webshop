<template>
	<b-breadcrumb :items="items" />
</template>

<style scoped>
.breadcrumb {
	background-color: var(--color-main);
	float: left;
}

.breadcrumb-item > a {
	color: #ffffff;
}

.breadcrumb-item.active {
	color: var(--color-4);
}

.breadcrumb-item + .breadcrumb-item::before {
	color: #ffffff;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'NavBreadcrumbs',
	data() {
		return {
			items: []
		}
	},
	computed: {
		...mapGetters({
			sectionById: 'sections/sectionById',
			chapterById: 'chapters/chapterById'
		})
	},
	watch: {
		$route() {
			const routeName = this.$route.name
			if (routeName.includes('chapters-id')) {
				this.updateItems()
			}
		}
	},
	mounted() {
		const routeName = this.$route.name
		if (routeName.includes('chapters-id')) {
			this.updateItems()
		}
	},
	methods: {
		updateItems() {
			let items = []
			if (this.$route.name === 'chapters-chapters-id') {
				const section = this.sectionById(
					parseInt(this.$route.params.id)
				)
				const chapter = this.chapterById(
					parseInt(this.$route.params.chapters)
				)
				items = [
					{
						text: chapter.header,
						href: '/chapters/' + chapter.id
					},
					{
						text: section.header,
						href: this.$route.path
					}
				]
			} else {
				const chapter = this.chapterById(
					parseInt(this.$route.params.id)
				)
				items = [
					{
						text: chapter.header,
						href: this.$route.path
					}
				]
			}
			this.items = items
		}
	}
}
</script>
