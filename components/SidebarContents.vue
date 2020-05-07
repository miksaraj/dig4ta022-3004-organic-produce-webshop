<template>
	<b-nav vertical>
		<div v-for="item in contentList" :key="item.id">
			<b-nav-item :class="{ dropdown: hasContent(item.id) }">
				<nuxt-link :to="'/chapters/' + item.id">
					<h3>{{ item.header }}</h3>
				</nuxt-link>
				<b-navbar-toggle
					v-if="hasContent(item.id)"
					:target="'chapter-contents-' + item.id"
				>
					<template v-slot:default="{ expanded }">
						<b-icon v-if="expanded" icon="caret-up" />
						<b-icon v-else icon="caret-down" />
					</template>
				</b-navbar-toggle>
			</b-nav-item>
			<b-collapse :id="'chapter-contents-' + item.id" is-nav>
				<div
					v-for="section in item.sections"
					:key="section.id"
					class="sub"
				>
					<b-nav-item>
						<nuxt-link
							:to="'/chapters/' + item.id + '/' + section.id"
						>
							{{ section.header }}
						</nuxt-link>
					</b-nav-item>
				</div>
			</b-collapse>
		</div>
	</b-nav>
</template>

<style scoped>
.navbar-toggler {
	float: right;
	position: relative;
	top: -38px;
	color: var(--color-4);
}

.nav.flex-column > div {
	margin-bottom: -28px;
}

.nav.flex-column > div > .nav-item:not(.dropdown) {
	margin-bottom: 24px;
}

.sub:first-child {
	margin-top: -8px;
}

.sub:last-child {
	margin-bottom: 32px;
}
</style>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'sidebarContents',
	data() {
		return {
			contentList: []
		}
	},
	computed: {
		...mapGetters('sections', ['sectionsByChapter']),
		chapters() {
			return this.$store.state.chapters.list
		}
	},
	mounted() {
		this.getContentList()
	},
	methods: {
		getContentList() {
			for (let i = 0; i < this.chapters.length; i++) {
				const sections = this.sectionsByChapter(this.chapters[i].id)
				this.contentList.push({
					id: this.chapters[i].id,
					header: this.chapters[i].header,
					sections
				})
			}
		},
		hasContent(id) {
			const chapter = this.contentList.find(element => element.id === id)
			if (chapter.sections.length > 0) {
				return true
			}
			return false
		}
	}
}
</script>
