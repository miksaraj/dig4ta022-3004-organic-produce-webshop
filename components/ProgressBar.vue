<template>
	<div>
		<b-row v-if="progress == 100">
			<b-icon icon="check-circle" />
			<p>Suoritettu! {{ done }} / {{ max }}</p>
		</b-row>
		<b-progress v-else-if="progress > 0" :max="max" striped animated>
			<b-progress-bar :value="done">
				<strong>{{ done }} / {{ max }}</strong>
			</b-progress-bar>
		</b-progress>
		<b-button v-else @click="start">
			Aloita!
		</b-button>
	</div>
</template>

<style scoped>
.btn {
	background-color: var(--color-3);
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'ProgressBar',
	data() {
		return {
			max: 0,
			done: 0
		}
	},
	watch: {
		$route() {
			if (this.bar) {
				if (this.$route.name === 'index') {
					this.getOverallProgress()
				} else {
					this.getItemProgress()
				}
			}
		}
	},
	computed: {
		...mapGetters({
			sectionsByChapter: 'sections/sectionsByChapter',
			sectionStructure: 'structure/sectionStructure',
			getProgressCount: 'progress/getProgressCount'
		}),
		item() {
			return this.$attrs.item
		},
		bar() {
			return this.$attrs.bar ? this.$attrs.bar : false
		},
		progress() {
			return (this.done / this.max) * 100
		}
	},
	mounted() {
		if (!this.item && this.$route.name === 'index') {
			this.getOverallProgress()
		} else {
			this.getItemProgress()
		}
	},
	methods: {
		getDone(type) {
			const done = []
			if (type === 'chapter') {
				// done = this.progressByChapter(this.item.id)
			} else if (type === 'section') {
				// done = this.progressBySection(this.item.id)
			}
			this.done = done.length
		},
		getItemProgress() {
			const completed = []
			let contentIds = []
			if (
				this.item.chapterId !== undefined ||
				this.$route.name === 'chapters-chapters-id'
			) {
				contentIds = this.countProgress(this.item.id)
			} else {
				const sections = this.sectionsByChapter(this.item.id)
				for (let i = 0; i < sections.length; i++) {
					const section = sections[i]
					contentIds = contentIds.concat(
						this.countProgress(section.id)
					)
				}
			}
			completed.push(this.getProgressCount(contentIds))
			this.max = contentIds.length
			this.done = completed.length > 0 ? completed.length : 0
		},
		countProgress(id) {
			const arr = []
			const content = this.sectionStructure(id)
			for (let i = 0; i < content.length; i++) {
				const element = content[i]
				arr.push(element.contentId)
			}
			return arr
		},
		getOverallProgress() {
			const contentIds = []
			const content = this.$store.state.content.list
			content.forEach(element => contentIds.push(element.id))
			this.done = this.getProgressCount(contentIds)
			this.max = contentIds.length
		},
		start() {
			this.$router.push(this.$route.path + '/' + this.item.id)
		}
	}
}
</script>
