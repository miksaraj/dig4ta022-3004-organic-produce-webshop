<template>
	<b-nav vertical>
		<div v-for="item in contentList" :key="item.id">
			<b-nav-item v-b-toggle="'course-contents-' + item.id">
				<h3>{{ item.header }}</h3>
			</b-nav-item>
			<b-collapse :id="'course-contents-' + item.id">
				<div v-for="part in item.modules" :key="part.id">
					<b-nav-item>{{ part.header }}</b-nav-item>
				</div>
			</b-collapse>
		</div>
	</b-nav>
</template>

<script>
import { mapGetters } from 'vuex'
export default {
	name: 'sidebar-contents',
	data() {
		return {
			contentList: []
		}
	},
	computed: {
		...mapGetters('modules', ['modulesByCourse']),
		courses() {
			return this.$store.state.courses.list
		}
	},
	mounted() {
		this.getContentList()
	},
	methods: {
		getContentList() {
			for (let i = 0; i < this.courses.length; i++) {
				const modules = this.modulesByCourse(this.courses[i].id)
				this.contentList.push({
					id: this.courses[i].id,
					header: this.courses[i].header,
					modules
				})
			}
		}
	}
}
</script>
