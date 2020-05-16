<template>
	<div>
		<b-row class="header-row">
			<h2>{{ route === 'index' ? 'Kokonaisedistys' : item.header }}</h2>
		</b-row>
		<b-row class="progress-bar-row">
			<progress-bar :item="item" :bar="true" />
		</b-row>
		<b-row>
			<h4>Tehtävät</h4>
			<b-navbar-toggle target="collapse-assignments">
				<template v-slot:default="{ expanded }">
					<b-icon v-if="expanded" icon="caret-up" />
					<b-icon v-else icon="caret-down" />
				</template>
			</b-navbar-toggle>
			<b-collapse visible id="collapse-assignments">
				<progress-list-group
					:items="assignments"
					:level="lvl"
					:theory="false"
				/>
			</b-collapse>
		</b-row>
		<b-row>
			<h4>Teoria</h4>
			<b-navbar-toggle target="collapse-theory">
				<template v-slot:default="{ expanded }">
					<b-icon v-if="expanded" icon="caret-up" />
					<b-icon v-else icon="caret-down" />
				</template>
			</b-navbar-toggle>
			<b-collapse id="collapse-theory">
				<progress-list-group
					:items="theoryContent"
					:level="lvl"
					:theory="true"
				/>
			</b-collapse>
		</b-row>
	</div>
</template>

<style scoped>
.progress-bar-row,
.header-row {
	display: flex;
	justify-content: center;
}

.progress-bar-row div {
	width: 85%;
	padding-bottom: 2rem;
}

.row:not(.progress-bar-row, .header-row) {
	display: flex;
	justify-content: center;
	padding-left: 1.2rem;
	padding-bottom: 2rem;
}

.collapse {
	width: 95%;
}
</style>

<script>
import { mapGetters } from 'vuex'
import ProgressBar from '~/components/ProgressBar.vue'
import ProgressListGroup from '~/components/ProgressListGroup.vue'
export default {
	name: 'SidebarProgress',
	components: {
		ProgressBar,
		ProgressListGroup
	},
	data() {
		return {
			route: 'index',
			item: null,
			theoryContent: [],
			assignments: [],
			lvl: 'overall'
		}
	},
	watch: {
		$route() {
			this.getRoute()
			this.getItem()
			this.getContent()
		}
	},
	computed: {
		...mapGetters({
			sectionById: 'sections/sectionById',
			sectionsByChapter: 'sections/sectionsByChapter',
			chapterById: 'chapters/chapterById',
			getContentList: 'structure/getContentList',
			fetchContent: 'content/fetchContent'
		})
	},
	mounted() {
		this.getRoute()
		this.getItem()
		this.getContent()
	},
	methods: {
		getRoute() {
			this.route = this.$route.name
		},
		getItem() {
			this.lvl = 'overall'
			if (this.route === 'chapters-id') {
				this.lvl = 'chapter'
				this.item = this.chapterById(parseInt(this.$route.params.id))
			} else if (this.route === 'chapters-chapters-id') {
				this.lvl = 'section'
				this.item = this.sectionById(parseInt(this.$route.params.id))
			}
		},
		getContent() {
			let sections = null
			if (this.lvl === 'chapter') {
				sections = this.sectionsByChapter(this.item.id)
			}
			const assignmentList = this.getContentList({
				type: 'assignments',
				lvl: this.lvl,
				sections,
				id: this.item ? this.item.id : null
			})
			const theoryContentList = this.getContentList({
				type: 'theory',
				lvl: this.lvl,
				sections,
				id: this.item ? this.item.id : null
			})
			this.assignments = this.fetchContent(assignmentList)
			this.theoryContent = this.fetchContent(theoryContentList)
		}
	}
}
</script>
